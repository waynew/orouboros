import signal
import time

print('Waiting')
now = time.time()
signal.sigwait([signal.SIGQUIT])
print('Waited for', time.time()-now)
