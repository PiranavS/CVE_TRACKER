from datetime import datetime
import time
import os
import watchdog

from apscheduler.schedulers.background import BackgroundScheduler

watchdog.runcheck()

if __name__ == '__main__':
    scheduler = BackgroundScheduler(timezone="Asia/Kolkata")
    scheduler.add_job(watchdog.runcheck, 'interval', minutes=30)
    scheduler.start()
    print('Press Ctrl+{0} to exit'.format('Break' if os.name == 'nt' else 'C'))

    try:
        # This is here to simulate application activity (which keeps the main thread alive).
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        # Not strictly necessary if daemonic mode is enabled but should be done if possible
        scheduler.shutdown()
