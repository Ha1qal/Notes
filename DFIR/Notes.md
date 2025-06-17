## Data Recovery from Mechanical Disks (HDDs)
### Physical Structure and Recovery Challenges

HDDs have moving read/write heads that write to and read from magnetic platters. Data loss can occur due to physical damage (platter scratches, motor failures), logical errors (accidental deletion, formatting), or software faults.
In cases of physical damage, recovery must be performed in cleanroom environments using specialized equipment.

#### Recovery Software and Hardware
Software: Tools like TestDisk, Recuva, R-Studio, and EaseUS Data Recovery Wizard can be used to recover accidentally deleted files, corrupted partitions, or formatted disks.
Hardware: For recovery operations, industry imaging tools like DeepSpar Disk Imager, cleanroom conditions, and micro-surgical tools may be required.

## Data Recovery from Solid-State Drives (SSDs)
### Physical Structure and Recovery Challenges

SSDs are electronic devices that record data onto NAND flash memory chips. Data loss may occur due to NAND wear, electronic failures, or logical errors.

The TRIM command helps maintain the performance and lifespan of SSDs because SSDs store data in flash memory cells, which have a limited number of write cycles. The TRIM command informs the operating system which data blocks are no longer in use, allowing the SSD to clear marks from these blocks. This reduces the time spent on finding free space and noticeably improves writing performance. Moreover, it eliminates the need to rewrite over unused data blocks, extending the SSD's lifespan. Finally, when data is deleted, there is no need for physical erasure on the SSD, speeding up the file deletion process.

However, one disadvantage of this advantage is that the activation of the TRIM command allows new data to be quickly written over deleted data, complicating the recovery process.

#### Recovery Software and Hardware

Software: Recovery from SSDs requires software that uses specialized algorithms. For example, Stellar Data Recovery and Ontrack EasyRecovery consider the characteristics of NAND flash memory and the effects of the TRIM command.

Hardware: SSD recovery processes may involve repairing electronic components or directly reading NAND flash memory chips. Therefore, specialized hardware such as NAND readers, memory chip removers, and electronic repair kits may be necessary.


## Risk of Data Loss
When the TRIM command is active in SSDs, recovering deleted data can become nearly impossible. In contrast, in HDDs, deleted data is generally recoverable unless new data has been written over it.

## FAT32
FAT32 stands for "File Allocation Table 32" and is one of the older file systems. It remains popular due to its wide compatibility with a range of devices. Introduced in 1996 with Windows 95 OSR2, FAT32 replaced FAT16 and was designed to support larger disk partitions and files. The technical structure and operating principles of FAT32 encompass several key features in the data storage and access processes.

## NTFS File System
NTFS stands for "New Technology File System" and was developed by Microsoft for Windows NT and later versions. With its advanced features and performance, it is the preferred file system in modern Windows environments. Focusing on performance, security, and data integrity, NTFS has a more complex structure than FAT32, designed to meet the advanced needs of modern computer systems.

![attribute](<Attribute in NTFS.png>)

## exFAT File System
exFAT (Extended File Allocation Table) was developed by Microsoft specifically for portable storage devices like flash drives and SD cards. It was designed to overcome the limitations of FAT32 and incorporate some of the features NTFS offers in portable storage environments. exFAT supports large files, offers better storage management, and is compatible with a wider range of devices.

![table](<comparison table.png>)

![ext](<EXT table.png>)

## Live Data Acquisition Tools

![alt text](LDA1.png)

![alt text](LDA2.png)

![alt text](LDA3.png)

![alt text](LDA4.png)

#### WinPmem
WinPmem is a useful, small, and installation-free Memory Dump tool. It is available at the following address:

WinPmem : https://github.com/Velocidex/WinPmem/releases
```bash
Winpmem_mini_x64_rc2.exe memdump.raw
```

#### FTK Imager
FTK Imager is a useful tool for taking images of both the drives connected to the system and the memory on Windows systems. The FTK Imager tool installation file can be downloaded from the following address:

FTK Imager : https://go.exterro.com/l/43312/2023-05-03/fc4b78

#### Volatility
Volatility is a powerful tool for analyzing both Linux and Windows memory images. Developed in Python, it can be used on almost any system with Python.

To install Volatility on Windows (assuming Python 3.11 is installed on the system), first download Volatility from the address below:

Volatility : https://github.com/volatilityfoundation/volatility3/releases
Volatility Plugins (for Windows) : https://github.com/volatilityfoundation/volatility/wiki/Command-Reference

To complete the installation of Volatility, download the “Microsoft C++ Build Tools”. It is available at the following address:

Microsoft C++ Build Tools : https://visualstudio.microsoft.com/visual-cpp-build-tools/

The Volatility installation requires a few more installations. One of them is the “Snappy” package for Python. There are different versions of this package available in many repositories, but the versions except the one downloaded from the link below do not work:

Python Snappy : https://download.lfd.uci.edu/pythonlibs/archived/python_snappy-0.6.1-cp311-cp311-win_amd64.whl
```bash
pip install .\python_snappy-0.6.1-cpp311-cpp311-win_amd64.whl
pip install -r .\requirements.txt
python .\vol.py
python .\vol.py -f memdump.mem windows.info.Info
```

## Dynamic Acquisition on Windows

![!\[alt text\](image.png)](DA.png)

Various system management and monitoring tools specifically designed for the Windows operating system facilitate dynamic data collection. These tools track system logs, performance metrics, and network activity. One notable example is the “ SysInternals Suite” , which is distributed free of charge by Microsoft. This suite contains a variety of tools, several of which are particularly useful for dynamic data acquisition. Below are some of these tools:

Process Explorer
AutoRuns
Regedit
Security Tools


## Data Acquisition Methods

#### Bit-Level Copy
An exact copy of physical or logical disks is made at the bit level (as a disk image). This method allows copying all data, configuration files, and hidden partitions on the disk.
The copy process transfers data from a source to a destination. The source and destination can be various data storage media such as hard disk drives, memory devices, or files.
A bit-level copy operation copies each bit of data individually. A unit of data can contain multiple bits, such as a byte (8 bits), a word (16 bits) or a dword (32 bits).

Bit-level copying can be performed using various methods. The most common methods are:

Sector Copy: This method copies each sector (512 bytes) on a disk one by one.
File Copy: This method copies all data in a file.
Memory Copy: This method copies all data in the memory of a computer system.


Errors can occur during the bit-level copy process. Error detection algorithms are used to detect and correct these errors.