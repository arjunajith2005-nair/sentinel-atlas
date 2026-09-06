import asyncio
import json
import logging
from datetime import datetime

# Set up dedicated async audit log
logging.basicConfig(
    filename="async_sentinel_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

class AsyncAuditor:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.is_running = False

    async def start(self):
        """Starts the background worker task."""
        self.is_running = True
        asyncio.create_task(self._process_queue())

    async def log_event_async(self, session_id: str, event_type: str, details: dict):
        """Non-blocking function to push audit jobs to the queue."""
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "event_type": event_type,
            "details": details
        }
        await self.queue.put(payload)

    async def _process_queue(self):
        """Continuously processes queued audit logs in the background."""
        while self.is_running:
            event = await self.queue.get()
            try:
                # Log asynchronously to file or database
                logging.info(json.dumps(event))
            except Exception as e:
                print(f"[AsyncAuditor Error]: {e}")
            finally:
                self.queue.task_done()

# Global auditor instance
auditor = AsyncAuditor()