# CICIDS2017 attack windows (pcap time base)

Derived by `replay/derive_windows_from_pcap.py`: attacker-IP packet bursts 
located in the raw pcaps (burst gap > 120s), matched to CSV labels.

| Day | Label | Start (UTC) | End (UTC) | Verified | Flows(CSV) |
|---|---|---|---|---|---|
| Friday | Bot | 07-07 12:00:45 | 12:59:00 | pcap-verified | 1966 |
| Thursday | Web Attack  Brute Force | 07-06 09:15:00 | 10:00:00 | csv-only | 1507 |
| Thursday | Web Attack  XSS | 07-06 10:15:00 | 10:35:00 | csv-only | 652 |
| Thursday | Web Attack  Sql Injection | 07-06 10:40:00 | 10:42:00 | csv-only | 21 |
| Tuesday | SSH-Patator | 07-04 02:09:00 | 03:11:00 | csv-only | 5897 |
| Tuesday | FTP-Patator | 07-04 09:17:00 | 10:30:00 | csv-only | 7938 |
| Wednesday- | Heartbleed | 07-05 03:12:00 | 03:32:00 | csv-only | 11 |
| Wednesday- | DoS Slowhttptest | 07-05 10:15:00 | 10:37:00 | csv-only | 5499 |
| Wednesday- | DoS Hulk | 07-05 10:43:00 | 11:07:00 | csv-only | 231073 |
| Wednesday- | DoS GoldenEye | 07-05 11:10:00 | 11:19:00 | csv-only | 10293 |
| Wednesday- | DoS slowloris | 07-05 14:24:00 | 18:55:17 | pcap-verified | 5796 |
