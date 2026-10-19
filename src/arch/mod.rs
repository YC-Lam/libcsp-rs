#[cfg(feature = "embassy")]
mod embassy;

#[cfg(feature = "embassy")]
pub use embassy::*;

#[cfg(all(feature = "tokio", not(feature = "embassy")))]
mod tokio;

#[cfg(all(feature = "tokio", not(feature = "embassy")))]
pub use tokio::*;
