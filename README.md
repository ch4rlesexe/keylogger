# Endpoint Monitoring and Keylogger Detection Lab

## For a full tutorial, please watch the following videos:
- https://www.youtube.com/watch?v=1m-BM52HIEI&t=637s -> Building a Windows Keylogger in C++
- https://www.youtube.com/watch?v=tPucv1BipKk -> How to build an Anti-Keylogger in C++ (AntiVirus)

## Overview
This project explores how keystroke logging works at the system level and how similar behavior can be identified from a defensive standpoint. It includes both logging implementations and a simple detection utility.

The goal is to better understand how user input can be captured in software, how these techniques interact with the operating system, and what limitations exist when trying to detect them.

## Components

### C++ Keylogger
- Uses the Windows API to capture keyboard input
- Logs keystrokes to a file
- Demonstrates low-level interaction with system input handling

### Python Keylogger
- Built using the `pynput` library
- Simpler implementation intended for comparison and learning
- Logs keystrokes to a local file

### Keylogger Detector (C++)
- Enumerates running processes
- Attempts to identify potentially suspicious programs
- Demonstrates basic endpoint monitoring concepts

## Purpose
This project was built as a learning exercise to understand both sides of a common security problem:
- How keylogging software operates
- Why detecting it is not straightforward

It is not intended to be a complete or production-ready detection system.

## Technologies
- C++
- Python
- Windows API
- Process enumeration

## Building and Running

### Python Keylogger
Install dependencies:
```

pip install pynput

```

Run:
```

python keylogger.py

```

### C++ Keylogger
Compile:
```

g++ keylogger.cpp -o keylogger

```

Run:
```

./keylogger

```

### Detector
Compile:
```

g++ keylogger_detector.cpp -o detector

```

Run:
```

./detector

```

## Disclaimer
This project is for educational use only. It should not be used on systems without permission.

