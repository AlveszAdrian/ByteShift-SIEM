SELECT message FROM events WHERE log_type = 'WinEvent-ETW' AND message LIKE '%"EventID":1,%' LIMIT 5;
