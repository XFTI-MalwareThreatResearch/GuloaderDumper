import win32process
import win32con
import win32api
import win32file
import win32event
import time

IOCTL_SEND_PID = 0x222000
exe_path = 'C:\\Users\\test\\Desktop\\test.exe'

startup_info = win32process.STARTUPINFO()
print('starting process')
process_info = win32process.CreateProcess(
    None,
    exe_path,
    None,
   None,
    False,
    win32con.CREATE_SUSPENDED,
    None,
    None,
    startup_info
)
print('started process')
h_process, h_thread, pid, tid = process_info
print('writing target pid')

pid_data = int.to_bytes(pid, 4, 'little')

print('Write target pid')

h = win32file.CreateFile(
    '\\\\.\\Global\\TestDevice',
    win32con.GENERIC_WRITE,
    0,
    None,
    win32con.OPEN_EXISTING,
    0,
    None
)
win32file.DeviceIoControl(h, IOCTL_SEND_PID, pid_data, None)
win32api.CloseHandle(h)
time.sleep(2)

win32process.ResumeThread(h_thread)
win32api.CloseHandle(h_thread)
win32api.CloseHandle(h_process)
hEvent = win32event.OpenEvent(win32con.SYNCHRONIZE, False, 'Global\\DumperWait')
timeout_minutes = 10
timeout_ms = timeout_minutes * 60 * 1000
result = win32event.WaitForSingleObject(hEvent, timeout_ms)
if result == win32con.WAIT_OBJECT_0:
    print('Worked!')
elif result == win32con.WAIT_TIMEOUT:
    print('error timeout')
    exit(1)
else:
    print('general error')
    exit(1)
print('Done')
exit(0)
    
