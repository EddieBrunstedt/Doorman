use doorman_core::storage::ExpiringStores;
use doorman_redis::{Namespace, RedisStorage};
use redis::aio::MultiplexedConnection;
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{GenericImage, ImageExt};
use testcontainers_modules::valkey::Valkey;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub enum Backend {
    Redis,
    Valkey,
    RedisCluster,
    ValkeyCluster,
}

// Only held so the container lives as long as the test.
pub type ContainerGuard = Box<dyn std::any::Any + Send>;

pub struct Server {
    pub host: String,
    pub port: u16,
    cluster: bool,
}

impl Server {
    pub fn url(&self) -> String {
        format!("redis://{}:{}", self.host, self.port)
    }

    // An ACL user that reaches only the namespace's keys and can't list the keyspace, so any
    // stray key or scan fails the test that made it.
    pub async fn confined_storage(&self, namespace: &str) -> RedisStorage {
        let user = format!("doorman-{}", Uuid::new_v4());
        let pattern = format!("~{}*", glob_escape(&format!("{{{namespace}}}:")));
        let _: () = redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&user)
            .arg("on")
            .arg(">secret")
            .arg(pattern)
            .arg("+@all")
            .arg("-scan")
            .arg("-keys")
            .arg("-randomkey")
            .query_async(&mut self.raw().await)
            .await
            .expect("create a confined ACL user");
        let url = format!("redis://{user}:secret@{}:{}", self.host, self.port);
        let storage = if self.cluster {
            RedisStorage::connect_cluster([url]).await
        } else {
            RedisStorage::connect(&url).await
        };
        storage
            .expect("connect as the confined user")
            .with_namespace(Namespace::new(namespace).expect("test namespace"))
    }

    pub async fn raw(&self) -> MultiplexedConnection {
        redis::Client::open(self.url())
            .expect("open raw redis client")
            .get_multiplexed_async_connection()
            .await
            .expect("open raw redis connection")
    }
}

fn glob_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

// Full of glob characters, so a key pattern built from it would reach other namespaces' keys.
pub fn namespace() -> String {
    format!("doorman-test:{}:*?[x]\\", Uuid::new_v4())
}

pub fn key(namespace: &str, rest: &str) -> String {
    format!("{{{namespace}}}:{rest}")
}

pub async fn start(backend: Backend) -> (ContainerGuard, Server) {
    match backend {
        Backend::Redis => {
            let node = Redis::default()
                .with_tag("7-alpine")
                .start()
                .await
                .expect("start redis container");
            let host = node.get_host().await.expect("container host").to_string();
            let port = node.get_host_port_ipv4(6379).await.expect("container port");
            (
                Box::new(node),
                Server {
                    host,
                    port,
                    cluster: false,
                },
            )
        }
        Backend::Valkey => {
            let node = Valkey::default()
                .start()
                .await
                .expect("start valkey container");
            let host = node.get_host().await.expect("container host").to_string();
            let port = node.get_host_port_ipv4(6379).await.expect("container port");
            (
                Box::new(node),
                Server {
                    host,
                    port,
                    cluster: false,
                },
            )
        }
        Backend::RedisCluster => start_cluster("redis", "7-alpine", "redis").await,
        Backend::ValkeyCluster => start_cluster("valkey/valkey", "8.0.2-alpine", "valkey").await,
    }
}

// One node owning every slot. A cluster checks that each command's and each script's keys share a
// slot whatever the node count, and one namespace never spans nodes, so redirects would test only
// the client.
async fn start_cluster(image: &str, tag: &str, binary: &str) -> (ContainerGuard, Server) {
    let node = GenericImage::new(image, tag)
        .with_exposed_port(6379.tcp())
        .with_cmd(["tail", "-f", "/dev/null"])
        .start()
        .await
        .expect("start cluster container");
    let host = node.get_host().await.expect("container host").to_string();
    let port = node.get_host_port_ipv4(6379).await.expect("container port");
    // The node announces the address the test reaches it on, since the cluster client connects
    // to whatever address the node gives for each slot.
    let script = format!(
        "{binary}-server --port 6379 --cluster-enabled yes --daemonize yes \
         --cluster-announce-hostname {host} --cluster-announce-port {port} \
         --cluster-preferred-endpoint-type hostname \
         && until {binary}-cli cluster addslotsrange 0 16383; do sleep 0.1; done \
         && until {binary}-cli cluster info | grep -q cluster_state:ok; do sleep 0.1; done"
    );
    node.exec(
        ExecCommand::new(["sh", "-c", &script]).with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
    )
    .await
    .expect("form a one-node cluster");
    (
        Box::new(node),
        Server {
            host,
            port,
            cluster: true,
        },
    )
}

pub async fn stores(backend: Backend) -> (ContainerGuard, ExpiringStores) {
    let (guard, stores, _, _) = stores_with_raw(backend).await;
    (guard, stores)
}

pub async fn stores_with_raw(
    backend: Backend,
) -> (
    ContainerGuard,
    ExpiringStores,
    MultiplexedConnection,
    String,
) {
    let (guard, server) = start(backend).await;
    let namespace = namespace();
    let storage = server.confined_storage(&namespace).await;
    (guard, storage.expiring(), server.raw().await, namespace)
}
