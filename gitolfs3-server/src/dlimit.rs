use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

// I know that this is pretty bad, but it's good enough (??) for now.
pub struct DownloadLimiter {
    current: u64,
    limit: u64,
}

impl DownloadLimiter {
    pub async fn new(limit: u64) -> Arc<Mutex<DownloadLimiter>> {
        let dlimit_str = match tokio::fs::read_to_string(".gitolfs3-dlimit").await {
            Ok(dlimit_str) => dlimit_str,
            Err(e) => {
                println!("Failed to read download counter, assuming 0: {e}");
                return DownloadLimiter { current: 0, limit }.auto_resetting();
            }
        };
        let current: u64 = match dlimit_str
            .parse()
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))
        {
            Ok(current) => current,
            Err(e) => {
                println!("Failed to read download counter, assuming 0: {e}");
                return DownloadLimiter { current: 0, limit }.auto_resetting();
            }
        };

        DownloadLimiter { current, limit }.auto_resetting()
    }

    fn auto_resetting(self) -> Arc<Mutex<Self>> {
        let limiter_ref = Arc::new(Mutex::new(self));
        let limiter_ref_cloned = limiter_ref.clone();
        tokio::spawn(async move {
            loop {
                println!("Resetting download counter in one hour");
                tokio::time::sleep(Duration::from_secs(3600)).await;
                println!("Resetting download counter");
                limiter_ref_cloned.lock().await.reset().await;
            }
        });
        limiter_ref
    }

    pub async fn request(&mut self, n: u64) -> tokio::io::Result<bool> {
        if self.current + n > self.limit {
            return Ok(false);
        }
        self.current += n;
        self.write_new_count().await?;
        Ok(true)
    }

    async fn reset(&mut self) {
        self.current = 0;
        if let Err(e) = self.write_new_count().await {
            println!("Failed to reset download counter: {e}");
        }
    }

    async fn write_new_count(&self) -> tokio::io::Result<()> {
        let cwd = tokio::fs::File::open(std::env::current_dir()?).await?;
        let mut file = tokio::fs::File::create(".gitolfs3-dlimit.tmp").await?;
        file.write_all(self.current.to_string().as_bytes()).await?;
        file.sync_all().await?;
        tokio::fs::rename(".gitolfs3-dlimit.tmp", ".gitolfs3-dlimit").await?;
        cwd.sync_all().await
    }
}
