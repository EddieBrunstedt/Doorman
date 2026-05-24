//! Tiny HTTP helpers shared by the built-in providers.

use serde::de::DeserializeOwned;

use super::provider::ProviderError;

/// Read a JSON body from a [`reqwest::Response`], turning a non-success
/// status or a decode failure into a [`ProviderError::Response`].
pub(super) async fn decode_json<T>(response: reqwest::Response) -> Result<T, ProviderError>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ProviderError::Response {
            status: status.as_u16(),
            message: body,
        });
    }
    response
        .json::<T>()
        .await
        .map_err(|e| ProviderError::Response {
            status: status.as_u16(),
            message: format!("decode error: {e}"),
        })
}
