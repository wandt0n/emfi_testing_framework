#!/usr/bin/python3
"""
Tool to run and evaluate EMFI attacks via Linux automatically
Usage:
    Define the parameters of your motor controllers, motors, the target, and ChipSHOUTER below
    This script requires a few packages. To set-up your venv, do as follows:
        1. Create a new python virtual env with "python3 -m venv pyenv" (requires apt install python3.12-venv)
        2. Activate with "source pyenv/bin/activate" (required at the start of every session)
        3. Install dependencies with "pip install textual pyserial pylablib chipshouter matplotlib pycryptodome"
        4. Start this script with "python emfi_framework.py" 
            optional: 
                --dryrun to use fake motors, chipshouter and target. Use --realtarget in addition to emulate everything but the target
                --jogonly to only enter the jog-menu and quit afterwards
                --quickdebug to skip all initialization questions. Use in combination with dryrun to quickly test changes to the script
    If you run into permission errors, you might need to add your user to the dialout group (sudo usermod -a -G dialout <username>, then reboot)
    I should've definitely separated this script into multiple files, but it was easier to transfer the newest version to the lab this way. However, the functions and classes in here are grouped based on functionallity, which is indicated by multi-line comments incorporating "###".
"""

__author__ = "Anton Kettling"
__version__ = "1.0.0"
__maintainer__ = "Anton Kettling"

import concurrent.futures
from pylablib.devices import Thorlabs
from chipshouter import ChipSHOUTER
from chipshouter.com_tools import Reset_Exception, Max_Retry_Exception
import serial
import time
import threading
import queue
import serial
import math
import binascii
import traceback
import pickle
import os
import glob
import csv
import matplotlib
matplotlib.use('Agg')  # Use the non-GUI backend
import matplotlib.pyplot as plt
import numpy as np
import os
from Crypto.Signature import PKCS1_v1_5 as signalgo
from Crypto.PublicKey import RSA #2048
from Crypto.Hash import SHA256
import random
from enum import Enum, auto

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Grid
from textual.widgets import Header, Footer, Log, ProgressBar, Input, Static, Label, Button
from textual.screen import Screen, ModalScreen
import logging
import argparse


"""
Motor parameters:
- Scaling factor between encoder counts and position in mm
- Scaling factors for velocity in mm/s
- Scaling factors for acceleration in mm/s^2
You can find them for your ThorLabs motor in the table of page 39 of this document:
https://www.thorlabs.com/Software/Motion%20Control/APT_Communications_Protocol_v40.pdf
"""
# Configuration values for MTS50-Z8
autodetect_params = False
EncCntPerMm = 34554.96
SF_velocity = 772981.3692
SF_acceleration = 263.8443072

# Movement parameters. Can be read out by using the Kinesis/XA software on Windows
max_velocity = 2.4
acceleration = 1.5

# Homing values for MTS50-Z8
home_direction="reverse"
limit_switch="reverse"
velocity=1.0
max_travel=50.0

"""
### Experiment parameters
"""

DEBUG = False

# MOVEMENT
AXES_SERIAL_NUMBERS = """Requires Dictionary with as many entries as motors that you use. Each entry must be: | Axis (string, e.g. "X") : Motor serial number (string) |""" # Serial numbers of your motor controllers. You can find them on their backside
TRIES_PER_POSITION = 300 # Number of tries per position before jogging the table to a new position
STEP_SIZE = 1.0 # mm, the step size for jogging the table
STARTING_DIRECTION = "right" # The direction in which the table should start jogging ("right"/"left")

# CHIPSHOUTER
CHIPSHOUTER_SERIAL_NUMBER = """Requires String: ChipSHOUTER comport serial number"""
TIP_USED = {"diameter_mm": 4, "winding": "CW"}

FAULT_PATTERN_START = [1]*3 + [0] #[0]*60 + [1] + [0]
FAULT_VOLTAGE_START = 280
DEAD_TIME_START = max(100, (500 // 30) + 1) # ms, the dead time of the ChipSHOUTER pulse, ChipSHOUTER charges 30V/ms in worst case
VARIABLE_VOLTAGE = False # Varies FAULT_VOLTAGE slightly within tries at the same position
VARIABLE_HIGH_TIME = True # Varies FAULT_PATTERN slightly within tries at the same position
MIN_VOLTAGE = 150
MAX_VOLTAGE = 500
MIN_HIGH_TIME_ns = 20
MAX_HIGH_TIME_ns = MIN_HIGH_TIME_ns*66
VARIABLE_DELAY = False
MIN_TRIES_PER_POSITION_AND_TIMING = 10 # decides on the granularity of the delay introduced for the fault on each position

# TARGET
TARGET_SERIAL_NUMBERS =  """Requires Dictionary with as many entries as targets that you want to test. Each entry must be: | Target comport serial number (string) : Target name (string) |"""
TARGET_BAUDRATE           = 115200
ALTERNATIVE_BAUDRATE     = 73529 # If set, switches baudrate if the target is not responding (backup-clock!)

ARDUINO_SERIAL_NUMBER = """Requires None or String: Arduino comport serial number. If omitted, set AUTO_RESET_TARGET to False""" # Used to trigger a reset of the target
ARDUINO_BAUDRATE = 115200
AUTO_RESET_TARGET = True # Resets target if unrecoverable state is detected. Requires Arduino to be connected to the PORST device of the target

HEADER_FILE_PATH = """Requires None or String: Path to header file""" # Path to a text file that contains the target banner, i.e., lines that are printed by the target on startup. If omitted, we can't detect a reset but wait for MAX_TIME_REQUIRED_FOR_TARGET_RESET_in_s if a reset is triggered by us

LEN_HEADER_STATIC_PART_TOP = 6 # The number of lines from the topof the file that are static, i.e., the same as in the file on every startup
LEN_HEADER_STATIC_PART_BOTTOM = 1

MAX_TIME_REQUIRED_FOR_TARGET_RESET_in_s = 30 # Reset timeout for if the header file is omitted or completion of a reset was not detected based on the provided header file

EXPECTED_DURATION_SIG_GEN_ms =  1500

REAL_SIGN_PARAMS = """Requires None or Dictionary: RSA signing parameters of the target as specified below. Used to verify signatures. Ommitting may require to comment out some parts of the code that verify signatures"""
# {
#     "PrivKey": {
#         "n": str("deadbeef..."
#                 ).lower().strip(),
#         "d": str("deadbeef..."
#                 ).lower().strip(),
#     },
#     "PubKey": {
#         "n": str("deadbeef..."
#                 ).lower().strip(),
#         "e": str("deadbeef..."
#                 ).lower().strip(),
#     }
# }

REAL_MSG        = """Requires None or String: Message that was hashed and signed, formatted as specified below. Used to verify signatures. Ommitting may require to comment out some parts of the code that verify signatures"""
# binascii.unhexlify('deadbeef...')

REAL_DIGEST     = """Requires None or String: Hashed and signed, formatted as specified below. Used to verify signatures. Ommitting may require to comment out some parts of the code that verify signatures"""
# str("deadbeef...").lower().strip()

VALID_SIGNATURE = """Valid signature of REAL_MSG, formatted as specified below. We used RSA PKCS#1v1.5. If you do not use a deterministic signing algorithm, you can omit providing this string and implement a signature validation where this variable is used instead."""
# str("8f21b2f2c8f3b87617813730134b2de9b75d0a47ee7ddf0b8afedb23961a0c529f5f0a80c9c473da991833fcc671e8ac97a400bef64658cfab195b506362f45ab4b10e04c4357e7ed0111cf38e60704e10ab0e287f34780162ca1164c0313abfd04ad543e2981d35f3c9c135bea8cc378182fc107b6f49622fc9228eea6c6124").lower().strip()

PREFIX = b'\x01\xfe\x01\xfe' # Static prefix for the signature, used to ensure the transmission was not faulted

ALARMS_DEFINED = """Requires Array of Strings: Alarm names transmitted by the taget as part of the onAlarm message"""


""" 
### Automatically set variables
START OF PROGRAM, DO NOT CHANGE PARAMS BEYOND THIS POINT
"""
parser = argparse.ArgumentParser(description='Lab Control Application')
parser.add_argument('--dryrun', action='store_true', help='Run with fake device emulator')
parser.add_argument('--noinit', action='store_true', help='[Deprecated] Skip any initialization steps taht require interaction')
parser.add_argument('--jogonly', action='store_true', help='Only enter the jog-menu and quit afterwards')
parser.add_argument('--quickdebug', action='store_true', help='Use together with dryrun. Tries to get you into the actual test as quickly as possible, selecting default options')
parser.add_argument('--realtarget', action='store_true', help='Use together with dryrun. Emulates all hardware except for the target')
args = parser.parse_args()

DEBUG = True if args.quickdebug else DEBUG
    

CHIPSHOUTER_PORT    = None # Something like "/dev/ttyUSB0", set automatically
TARGET_PORT         = None # Something like "/dev/ttyUSB0", set automatically
ARDUINO_PORT        = None # Something like "/dev/ttyUSB0", set automatically

target_lock = threading.RLock()
dummy_lock = threading.Lock()
event_queue = queue.Queue()
stop_event = threading.Event()

DELAY_INCREMENT_in_ms = None
NO_OF_TRIES_PER_DELAY_INCREMENT = None

POS_COUNTER = 0
SIG_COUNTER = 0
CS_DISABLED_FOR_COUNTER = 0

DIRECTION = STARTING_DIRECTION
STARTING_POSITION = None
ALLOW_MOVEMENT = True
FAULT_PATTERN = FAULT_PATTERN_START
FAULT_VOLTAGE = FAULT_VOLTAGE_START
FAULT_VOLTAGE_START_AT_STEP = FAULT_VOLTAGE_START
DEAD_TIME = DEAD_TIME_START
VARIABLE_STATE = 0
FAULT_VOLTAGE_INCREMENTS = 10
FAULT_PATTERN_INCREMENTS = MIN_HIGH_TIME_ns

# size of the die that shall be probed
BOUNDARIES = {
    "X": {
        "LEFT":     None,  # mm
        "RIGHT":    None,  # mm
    },
    "Y": {
        "UP":       None,   # mm
        "DOWN":     None,   # mm
    },
    "Z": {
        "UP":       None,   # mm
        "DOWN":     None,   # mm
    }
}

REFERENCE_POINT = {
    "X": None,
    "Y": None,
}

CURRENT_POSITION = {
    "X": None,
    "Y": None,
    "Z": None
}

TRIES_LEFT_PER_POSITION = TRIES_PER_POSITION
TRIES_LEFT_PER_POSITION_AND_TIME = None
CONFIRMED_FAULTS = []
CONFIRMED_ALARMS = []
SIGNATURES_PARAMS = []

LOOPING_COUNTER_UNPARSEABLE_SIGNATURE = 60
SHOW_UART = True if args.quickdebug else False

AXES = None
CS = None
TARGET = None
DUMMY_TARGET = None

CURRENT_TIMING = {"after_trigger_ms": None, "trigger_duration_ns": None, "after_sign_ms": None}
PAST_TIMINGS = {"between_trigger_and_signGen_ms": [], "trigger_duration_ns": []}

CURRENT_PROGRESS = 0
TOTAL_PROGRESS = 1
STEPS_REQUIRED = 0

def getTime(date=False, filehandle=False):
    if date and filehandle:
        return time.strftime("%Y-%m-%d_%H-%M-%S" , time.localtime(time.time()))
    elif date:
        return time.strftime("%H:%M:%S (%d.%m.%Y)" , time.localtime(time.time()))
    else:
        return time.strftime("%H:%M:%S" , time.localtime(time.time()))
    
# Logging setup
BASENAME_FILES = getTime(date=True, filehandle=True)
LOGFILE = BASENAME_FILES + ".log"
CHECKPOINT_FILE = None
BOUNDARIES_FILE = "boundariesv3.pkl"
TARGET_NAME = ""
class NoConsoleOnlyFilter(logging.Filter):
    def filter(self, record):
        return not getattr(record, "console_only", False)

logger = logging.getLogger("lab")
logger.setLevel(logging.DEBUG) if DEBUG else logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOGFILE, mode="a")
file_handler.setLevel(logging.DEBUG) if DEBUG else file_handler.setLevel(logging.INFO)
file_handler.addFilter(NoConsoleOnlyFilter())
formatter = logging.Formatter("[%(asctime)s] | %(levelname)-7s | %(message)s", datefmt="%m/%d/%y %H:%M:%S")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def update_logfile(new_basename):
    global logger, LOGFILE, BASENAME_FILES

    old_logfile = LOGFILE
    new_logfile = new_basename + ".log"

    # Remove and close old file handler(s)
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.close()
            logger.removeHandler(handler)

    # Rename the file on disk
    try:
        os.rename(old_logfile, new_logfile)
    except OSError as e:
        logger.error(f"Failed to rename logfile from {old_logfile} to {new_logfile}. Continuing with old logfile.")
        return

    # Update basename and logfile
    BASENAME_FILES = new_basename
    LOGFILE = BASENAME_FILES + ".log"

    # Add new file handler
    file_handler = logging.FileHandler(LOGFILE, mode="a")
    file_handler.setLevel(logging.DEBUG) if DEBUG else file_handler.setLevel(logging.INFO)
    file_handler.addFilter(NoConsoleOnlyFilter())
    formatter = logging.Formatter("[%(asctime)s] | %(levelname)-7s | %(message)s", datefmt="%m/%d/%y %H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info(f"Logfile updated to {LOGFILE}")       

"""
### Dummy structures for testing
"""
class DummyAxis:
    def __init__(self, name):
        self.name = name
        self.position = 7.3
        self.homed = True if args.quickdebug else False
        self.step_size = 3.0

    def is_opened(self):
        return True
    
    def is_moving(self):
        return False
    
    def wait_for_stop():
        return
    
    def stop(self, immediate=True, sync=True):
        logger.debug(f"Dummy {self.name}-Axis received an emergency stop")

    def move_to(self, position):
        self.position = position
        time.sleep(0.3)
        logger.debug(f"Dummy {self.name}-Axis moved to {position:.3f}mm")

    def jog(self, direction):
        if direction == "+" :
            self.position += self.step_size
            time.sleep(0.3)
        elif direction == "-":
            self.position -= self.step_size
            time.sleep(0.3)
    
    def setup_jog(self, mode=None, step_size=None, min_velocity=None, acceleration=None, max_velocity=None, stop_mode=None, channel=None, scale=True):
        self.step_size = step_size
        logger.debug(f"Dummy {self.name}-Axis set jog-speed to {self.step_size:.3f}mm")
        return

    def get_position(self):
        return self.position
    
    def is_homed(self):
        return self.homed
    
    def home(self):
        time.sleep(1)
        self.homed = True
        logger.debug(f"Dummy {self.name}-Axis homed at position {self.position:.3f}mm")
        return
    
    def wait_for_home(self):
        self.home()
    
    def get_velocity_parameters(self):
        return 0, acceleration, max_velocity
    
    def get_scale(self):
        return EncCntPerMm, SF_velocity, SF_acceleration
    
    def get_scale_units(self):
        return "user"

    def blink(self):
        logger.debug(f"Dummy {self.name}-Axis blinked")

    def close(self):
        logger.debug(f"Dummy {self.name}-Axis closed")
        return True

class DummyChipSHOUTER:

    class DummyVoltage:
        def __init__(self, value):
            self.set = value
            self.measured = value
    
    def __init__(self, port=None):
        self.port = port
        self.id = "FAKE_ID"
        self.api_version = "FAKE_API"
        self.pat_wave = [0]*60 + [1] + [0]
        self.pat_enable = 1
        self.pulse = type("Pulse", (), {"repeat": 1, "deadtime": 1})()
        self.hwtrig_term = 1
        self.hwtrig_mode = 1
        self.emode = 0
        self.mute = 1
        self.armed = 0
        self.faults_current = []
        self._voltage = self.DummyVoltage(350)
        self.reset = 0

    @property
    def state(self):
        return "armed" if self.armed else "disarmed"

    @property
    def voltage(self):
        return self._voltage

    @voltage.setter
    def voltage(self, value):
        self._voltage.set = value
        self._voltage.measured = value

    @property
    def pat_wave(self):
        # Return as string of 0s and 1s
        return ''.join(str(x) for x in self._pat_wave)

    @pat_wave.setter
    def pat_wave(self, value):
        # Accept list/array of ints
        if isinstance(value, (list, tuple)) and all(x in (0, 1) for x in value):
            self._pat_wave = list(value)
        else:
            logger.error("pat_wave must be a list or tuple of 0s and 1s")
            stop_event.set()

    def ready_for_commands(self):
        pass

    def status(self):
        return True

    def disconnect(self):
        pass

class DummyTarget:

    def __init__(self, reset_enabled=True, faults_enabled=False, deterministic_errors=True, error_probability=0.05, start_on_error=0, delay=(EXPECTED_DURATION_SIG_GEN_ms / 1000), keyword="Signature:", payload=(PREFIX + binascii.unhexlify(VALID_SIGNATURE))):
        self.reset_enabled = reset_enabled
        self.faults_enabled = faults_enabled
        self.deterministic_errors = deterministic_errors
        self.error_probability = error_probability
        self.delay = delay
        self.keyword = keyword
        self.real_payload = payload

        # internal states
        self.payload = payload
        self.next_error = start_on_error
        self.messages_since_last_fault = 0
        self.fault_state = {
            "keyword": {
                "unparseable": False,
                "long": False,
                "empty": False,
                "no": False,
            },
            "message": {
                "unparseable": False,
                "long": False,
                "empty": False,
                "no": False,
            },
            "power": {
                "loss": False,
            }
        }
        self.reset_required = False
        self.reset_buffer = []
        self.keyword_sent = False
        with open(HEADER_FILE_PATH, "r") as f:
            self.header_lines = [line for line in f.readlines()]
    
    def close(self):
        pass

    def reset(self):
        with dummy_lock:
            self.reset_required = False
            self.messages_since_last_fault = 0
            self.fault_state = {
                "keyword": {
                    "unparseable": False,
                    "long": False,
                    "empty": False,
                    "no": False,
                },
                "message": {
                    "unparseable": False,
                    "long": False,
                    "empty": False,
                    "no": False,
                }
            }
            for line in self.header_lines:
                self.reset_buffer.append(line)
        time.sleep(3)
        return

    def read_until(self, delimiter, size=None):
        with dummy_lock:

            self.payload += delimiter
            self.real_payload += delimiter

            # After reset, we simulate reporting the startup banner
            if self.reset_buffer:
                return self.reset_buffer.pop(0).encode()
            
            # Set any of the pre-configured error-states
            if self.reset_enabled and not self.reset_required and (self.deterministic_errors or random.random() <= self.error_probability or FAULT_VOLTAGE >= 300):
                if self.messages_since_last_fault > 20:
                    self.reset_required = True
                    fault_type_keyword = ""
                    fault_type_message = ""

                    if self.deterministic_errors:
                    
                        if self.next_error == 0:
                            fault_type_keyword = "unparseable"
                        elif self.next_error == 1:
                            fault_type_keyword = "empty"
                        elif self.next_error == 2:
                            fault_type_keyword = "long"
                        elif self.next_error == 3:
                            fault_type_keyword = "no"
                        elif self.next_error == 4:
                            fault_type_keyword = "unparseable"
                            fault_type_message = "unparseable"
                        elif self.next_error == 5:
                            fault_type_keyword = "unparseable"
                            fault_type_message = "long"
                        elif self.next_error == 6:
                            fault_type_keyword = "unparseable"
                            fault_type_message = "empty"
                        elif self.next_error == 7:
                            fault_type_keyword = "unparseable"
                            fault_type_message = "no"
                        elif self.next_error == 8:
                            fault_type_keyword = "empty"
                        elif self.next_error == 9:
                            fault_type_keyword = "empty"
                            fault_type_message = "unparseable"
                        elif self.next_error == 10:
                            fault_type_keyword = "empty"
                            fault_type_message = "long"
                        elif self.next_error == 11:
                            fault_type_keyword = "empty"
                            fault_type_message = "empty"
                        elif self.next_error == 12:
                            fault_type_keyword = "empty"
                            fault_type_message = "no"
                        elif self.next_error == 13:
                            fault_type_keyword = "no"
                        elif self.next_error == 14:
                            fault_type_keyword = "no"
                            fault_type_message = "unparseable"
                        elif self.next_error == 15:
                            fault_type_keyword = "no"
                            fault_type_message = "long"
                        elif self.next_error == 16:
                            fault_type_keyword = "no"
                            fault_type_message = "empty"
                        elif self.next_error == 17:
                            fault_type_keyword = "no"
                            fault_type_message = "no"
                        elif self.next_error == 181:
                            fault_type_keyword = "long"
                            fault_type_message = "unparseable"
                        elif self.next_error == 19:
                            fault_type_keyword = "long"
                            fault_type_message = "long"
                        elif self.next_error == 20:
                            fault_type_keyword = "long"
                            fault_type_message = "empty"
                        elif self.next_error == 21:
                            fault_type_keyword = "long"
                            fault_type_message = "no"
                        elif self.next_error == 22:
                            fault_type_message = "unparseable"
                        elif self.next_error == 23:
                            fault_type_message = "empty"
                        elif self.next_error == 24:
                            fault_type_message = "long"
                        elif self.next_error == 25:
                            fault_type_message = "no"

                    else:
                        fault_type_keyword = random.choice(list(self.fault_state["keyword"].keys()))
                        fault_type_message = random.choice(list(self.fault_state["message"].keys()))

                    self.fault_state["keyword"][fault_type_keyword] = True
                    self.fault_state["message"][fault_type_message] = True

                    if fault_type_keyword and fault_type_message:
                        logger.info(f"Simulating fault state of target with {fault_type_keyword} keyword and {fault_type_message} message")
                    elif fault_type_keyword:
                        logger.info(f"Simulating fault state of target with {fault_type_keyword} keyword")
                    elif fault_type_message:
                        logger.info(f"Simulating fault state of target with {fault_type_message} message")
                    else:
                        logger.error("Simulating fault state of target with no keyword and no message, this should not happen!")

                    if self.next_error < 25:
                        self.next_error += 1
                    else:
                        self.next_error = 0
                        if self.deterministic_errors: logger.info("Simulated all possible fault states!")
                else:
                    self.messages_since_last_fault += 1
                    logger.debug(f"DummyTarget has sent {self.messages_since_last_fault} messages since last fault")

            if self.fault_state["keyword"]["no"] and self.fault_state["message"]["no"]:
                logger.debug("DummyTarget simulates power loss")
                raise Exception("Simulating power loss as fault state of target")
            
            time.sleep(self.delay)
            
            # Send keyword first
            if not self.keyword_sent:

                self.keyword_sent = True

                if not self.reset_required:
                    logger.debug("DummyTarget sends keyword")
                    return self.keyword.encode()
                
                elif self.fault_state["keyword"]["unparseable"]:
                    logger.debug("DummyTarget sends unparseable keyword")
                    return self.keyword.encode()[:(len(self.keyword)//2)] + b'\xff' * (len(self.keyword)//2)
                
                elif self.fault_state["keyword"]["long"]:
                    logger.debug("DummyTarget sends long keyword")
                    return (self.keyword + 2000 * self.keyword[-1]).encode()
                
                elif self.fault_state["keyword"]["empty"]:
                    logger.debug("DummyTarget sends empty keyword")
                    return "".encode()
                
                elif self.fault_state["keyword"]["no"]:
                    logger.debug("DummyTarget sends no keyword")
                    pass
                
            
            # Simulate random faults in the upper right corner of the chip
            if self.faults_enabled:
                self.payload = PREFIX + binascii.unhexlify("2df71ed42d6bf9174c938555aae4f3ddf50c1bdcb3ee226adeb647612c45f5c32ea27075937e5ee98d9879e4acbd4dd63a7b40b5b35f3f6f8a76f17845a96f210e28ab25979176ed09ea287c229dfcebc2cd7d511d8e8a3c55bcbee7a16093343f1b670bc180ead2f26af5d391ef29e15cf0707f588abc9c3e11365ca96ce529") + delimiter
                # raise NotImplementedError("DummyTarget does not support faults as the .get_position does not care for the REFERENCE_POINT")
                # x_pos = AXES["X"].get_position()
                # y_pos = AXES["Y"].get_position()
                # x_left = BOUNDARIES["X"]["LEFT"]
                # x_right = BOUNDARIES["X"]["RIGHT"]
                # y_up = BOUNDARIES["Y"]["UP"]
                # y_down = BOUNDARIES["Y"]["DOWN"]
                # if (
                #     x_left >= x_pos >= (x_left + x_right) / 2 and
                #     y_up >= y_pos >= (y_up + y_down) / 2
                # ):
                #     self.payload = self.real_payload[:-1] + b'A'

            else:
                self.payload = self.real_payload

            # Send actual message second
            self.keyword_sent = False

            if not self.reset_required:
                logger.debug(f"DummyTarget sends message")
                return self.payload
                
            elif self.fault_state["message"]["unparseable"]:
                logger.debug(f"DummyTarget sends unparseable message")
                return self.payload[:(len(self.payload)//2)] + b'\xff' * (len(self.payload)//2)
            
            elif self.fault_state["message"]["long"]:
                    logger.debug("DummyTarget sends long message")
                    return (self.payload + 2000 * self.payload[-1])
            
            elif self.fault_state["message"]["empty"]:
                logger.debug(f"DummyTarget sends empty message")
                return ""
            
            elif self.fault_state["message"]["no"]:
                logger.debug(f"DummyTarget sends no message")
                pass

            return b""


""" 
Motor-related functions
"""

class JogInteractively(Screen):
    """Screen for interactive jogging of axes and setting boundaries."""

    def __init__(self, axes, msg=""):
        super().__init__()
        self.axes = axes
        self.starting_speed = 3
        self.speed = 3
        self.levels = {1: 0.01, 2: 0.1, 3: 0.5, 4: 3.0}
        self.boundary_set = False
        self.msg = f"{msg} | Speed: "

    def compose(self) -> ComposeResult:
        yield Static(self.msg + " " + "+" * self.speed, id="jog_msg")
        if args.dryrun:
            yield Static("This is a dry-run. Jog the fake motors with the following knobs.", id="dryrun_msg")
            if args.dryrun:
                if "X" in self.axes:
                    yield Static(f"Position X: {self.axes["X"].get_position():.3f}mm", id="pos-x")
                if "Y" in self.axes:
                    yield Static(f"Position Y: {self.axes["Y"].get_position():.3f}mm", id="pos-y")
                if "Z" in self.axes:
                    yield Static(f"Position Z: {self.axes["Z"].get_position():.3f}mm", id="pos-z")
                if "X" in self.axes:
                    yield Grid(
                        Button("X-Left", id="jog_positive"),
                        Button("X-Right", id="jog_negative")
                    )
                if "Y" in self.axes:
                    yield Grid(
                        Button("Y-UP", id="jog_positive"),
                        Button("Y-DOWN", id="jog_negative")
                    )
                if "Z" in self.axes:
                    yield Grid(
                        Button("Z-UP", id="jog_negative"),
                        Button("Z-DOWN", id="jog_positive")
                    )
        yield Label("Use + or - to change speed. Confirm when at boundary.", id="instructions")
        yield Grid(
            Button("+", id="speed_up"),
            Button("-", id="speed_down"),
            Button("Confirm Position", id="confirm"),
            id="jog_controls"
        )

    def on_mount(self):
        for axis, motor in self.axes.items():
            motor.setup_jog(step_size=self.levels.get(self.starting_speed, 0.5))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        
        if args.dryrun:
            if event.button.id == "jog_positive":
                axis_str = str(event.button.label)[:1]
                self.axes[axis_str].jog(direction="+")
                self.query_one("#pos-"+axis_str.lower()).update(f"Position {axis_str}: {self.axes[axis_str].get_position():.3f}")
                return

            elif event.button.id == "jog_negative":
                axis_str = str(event.button.label)[:1]
                self.axes[axis_str].jog(direction="-")
                self.query_one("#pos-"+axis_str.lower()).update(f"Position {axis_str}: {self.axes[axis_str].get_position():.3f}")
                return
            
        jog_msg = self.query_one("#jog_msg")

        if event.button.id == "speed_up":
            if self.speed < 4:
                self.speed += 1
                for axis, motor in self.axes.items():
                    motor.setup_jog(step_size=self.levels.get(self.speed, 0.5))
                jog_msg.update(self.msg + "+" * self.speed)
            else:
                jog_msg.update(self.msg + "+" * self.speed + " (max)")

        elif event.button.id == "speed_down":
            if self.speed > 1:
                self.speed -= 1
                for axis, motor in self.axes.items():
                    motor.setup_jog(step_size=self.levels.get(self.speed, 0.5))
                jog_msg.update(self.msg + "+" * self.speed)
            else:
                jog_msg.update(self.msg + "+" * self.speed + " (min)")

        elif event.button.id == "confirm":
            self.boundary_set = True
            self.dismiss()

class MoveInteractively(Screen):

    def __init__(self, axes, msg, move_func, move_msg="Moving along boundaries..."):
        super().__init__()
        self.axes = axes
        self.msg = msg
        self.move_msg = move_msg
        self.running = False
        self.move_func = move_func
        
    def compose(self) -> ComposeResult:
        if args.dryrun:
            yield Static(f"Position X: {self.axes["X"].get_position():.3f}mm", id="x-pos")
            yield Static(f"Position Y: {self.axes["Y"].get_position():.3f}mm", id="y-pos")
            yield Static(f"Position Z: {self.axes["Z"].get_position():.3f}mm", id="z-pos")
        yield Static(self.msg, id="message")
        yield Button("Start", id="start_stop")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_stop":
            if self.running:
                self.query_one("#message").update("E-Stop triggered.")
                self.app.action_emergency_stop(self.axes)
                self.dismiss()
            else:
                self.query_one("#message").update(self.move_msg)
                self.query_one("#start_stop").label = "Stop"
                threading.Thread(target=self.move_func, args=(self,self.axes), daemon=True).start()

    def on_mount(self) -> None:
        if args.dryrun:
            self.set_interval(0.1, self.update_ui)

    def update_ui(self):
        if args.dryrun:
            self.query_one("#x-pos").update(f"Position X: {self.axes['X'].get_position():.3f}mm")
            self.query_one("#y-pos").update(f"Position Y: {self.axes['Y'].get_position():.3f}mm")
            self.query_one("#z-pos").update(f"Position Z: {self.axes['Z'].get_position():.3f}mm")

async def init_axes(homing=True, app=None):
    logger.info("Initialization of Motor Controllers.")
    found_devices = {}

    if args.dryrun:
        found_devices = {"X": DummyAxis("X"), "Y": DummyAxis("Y"), "Z": DummyAxis("Z")}
        logger.warning("Dry-run. Using Dummy Axes instead of real ones.")
    else:
        for axis, sn in AXES_SERIAL_NUMBERS.items():

            port = find_tty_path(sn)

            if port: 
                if autodetect_params:
                    found_devices[axis] = Thorlabs.KinesisMotor(port, scale = "stage")
                else:
                    found_devices[axis] = Thorlabs.KinesisMotor(port, scale = (EncCntPerMm, SF_velocity, SF_acceleration))
                    found_devices[axis].setup_velocity(max_velocity=max_velocity, acceleration=acceleration)
                    if homing:
                        found_devices[axis].setup_homing

                serial_no, model_no, fw_ver, hw_type, hw_ver, mod_state, nchannels, notes = found_devices[axis].get_device_info()

                # if serial_no != serial_number: # Broken as serial number is not correctly returned by the API
                #     logger.error(f"Associated device with s/n {serial_number} but device returns s/n {serial_no}")
                    # stop_event.set()

                logger.info(f"   - Initialized {axis} as {model_no}v{hw_ver} (fw_ver {fw_ver}) with state {mod_state}")

    if not found_devices:
        logger.error("No K-Cubes found. Aborting...")
        return

    if not len(found_devices) == len(AXES_SERIAL_NUMBERS):
        logger.error(f"Found {len(found_devices)} axes, but {len(AXES_SERIAL_NUMBERS)} were expected. Found: {list(found_devices.keys())}, expected: {list(AXES_SERIAL_NUMBERS.keys())}")
        return

    logger.info("Checking motor parameters")
    
    for axis, motor in found_devices.items():

        if autodetect_params:
            logger.warning(f"   - {axis}: Uses {motor.get_scale()} (autodetect, cannot determine if this is correct)")

        else:
            scale = motor.get_scale()
            min_v, acc, max_v = motor.get_velocity_parameters()
            warnings=[]

            if scale != (EncCntPerMm, SF_velocity, SF_acceleration):
                logger.error(f"Axis {axis} has scale of {scale} instead of {(EncCntPerMm, SF_velocity, SF_acceleration)}. Aborting...")
                return

            if max_v > max_velocity:
                logger.error(f"Axis {axis} has max velocity of {max_v} instead of {max_velocity}. Aborting...")
                return

            if max_velocity - max_v > 0.1:
                warnings.append(f"Has max velocity of {max_v} instead of {max_velocity}")

            if acc > acceleration:
                logger.error(f"Axis {axis} has acceleration of {acc} instead of {acceleration}. Aborting...")
                return

            if acceleration - acc > 0.1:
                warnings.append(f"Has acceleration of {acc} instead of {acceleration}")

            if not autodetect_params and motor.get_scale_units() != "user":
                warnings.append(f"Does indicate not to use the user-supplied values but is in range of them")
            
            if warnings:
                logger.info(f"   - {axis}: OK. Warnings: {', '.join(warnings)}")
            else:
                logger.info(f"   - {axis}: OK ")

    if homing:
        await home_axes_interactively(found_devices, app=app)

    if (not found_devices):
        raise Exception("Initializing axes returned no axes")

    return found_devices

def selfheal_axes():
    # The init_axes() function is async because it is used as part of the Textual UI Lab Initialization.
    # However, it is also used in other places where async is not possible, e.g., error handling while the script runs
    # This can probably be solved in a more elegant way, but for now, we just duplicate most of init_axes' functionality here without async/await

    try:
        logger.info("Initialization of Motor Controllers due to selfheal.")
        found_devices = {}

        if args.dryrun:
            found_devices = {"X": DummyAxis("X"), "Y": DummyAxis("Y"), "Z": DummyAxis("Z")}
            logger.warning("Dry-run. Using Dummy Axes instead of real ones.")
        else:
            for axis, sn in AXES_SERIAL_NUMBERS.items():

                port = find_tty_path(sn)

                if port: 
                    if autodetect_params:
                        found_devices[axis] = Thorlabs.KinesisMotor(port, scale = "stage")
                    else:
                        found_devices[axis] = Thorlabs.KinesisMotor(port, scale = (EncCntPerMm, SF_velocity, SF_acceleration))
                        found_devices[axis].setup_velocity(max_velocity=max_velocity, acceleration=acceleration)
                        found_devices[axis].setup_homing

                    serial_no, model_no, fw_ver, hw_type, hw_ver, mod_state, nchannels, notes = found_devices[axis].get_device_info()

                    logger.info(f"   - Initialized {axis} as {model_no}v{hw_ver} (fw_ver {fw_ver}) with state {mod_state}")

        if not found_devices:
            raise Exception("No K-Cubes found. Aborting...")

        if not len(found_devices) == len(AXES_SERIAL_NUMBERS):
            raise Exception(f"Found {len(found_devices)} axes, but {len(AXES_SERIAL_NUMBERS)} were expected. Found: {list(found_devices.keys())}, expected: {list(AXES_SERIAL_NUMBERS.keys())}")

        logger.info("Checking motor parameters")
        
        for axis, motor in found_devices.items():

            if autodetect_params:
                logger.warning(f"   - {axis}: Uses {motor.get_scale()} (autodetect, cannot determine if this is correct)")

            else:
                scale = motor.get_scale()
                min_v, acc, max_v = motor.get_velocity_parameters()
                warnings=[]

                if scale != (EncCntPerMm, SF_velocity, SF_acceleration):
                    raise Exception(f"Axis {axis} has scale of {scale} instead of {(EncCntPerMm, SF_velocity, SF_acceleration)}. Aborting...")

                if max_v > max_velocity:
                    raise Exception(f"Axis {axis} has max velocity of {max_v} instead of {max_velocity}. Aborting...")

                if max_velocity - max_v > 0.1:
                    warnings.append(f"Has max velocity of {max_v} instead of {max_velocity}")

                if acc > acceleration:
                    raise Exception(f"Axis {axis} has acceleration of {acc} instead of {acceleration}. Aborting...")

                if acceleration - acc > 0.1:
                    warnings.append(f"Has acceleration of {acc} instead of {acceleration}")

                if not autodetect_params and motor.get_scale_units() != "user":
                    warnings.append(f"Does indicate not to use the user-supplied values but is in range of them")
                
                if warnings:
                    logger.info(f"   - {axis}: OK. Warnings: {', '.join(warnings)}")
                else:
                    logger.info(f"   - {axis}: OK ")

        home_axes(found_devices)

        global AXES
        AXES = found_devices

        return found_devices
        
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        if tb:
            filename, lineno, func, text = tb[-1]
            logger.error(f"Error while trying to selfheal axes: {filename} raised an error on line {lineno} (func {func}): {text}\n{e}")
        else:
            logger.error(f"Error while trying to selfheal axes:\n{e}")  

def deinit_axes(axes):
    if not axes:
        logger.info("No Axes to deinitialize")

    else:
        try:
            for axis, motors in axes.items():
                motors.close()
        except Exception as e:
            logger.error(f"Error closing axes: {e}")
            return
        logger.info("Deinitialized all axes ")

async def home_axes_interactively(axes, app): 
    def perform_homing(self, axes):
        self.running = True
        home_axes(axes)
        self.running = False
        self.dismiss()
    
    requires_homing = False

    for axis, motor in axes.items():
        if not motor.is_homed():
            requires_homing = True
            break

    if requires_homing:
        
        if app is not None:
            await app.push_screen_wait(
                MoveInteractively(  axes, 
                                    "At least one axis require homing. This will move the Z-axis in the upwards position first. Then, it might move other axes to their null coordinate.\nKeep clear of the motors and press Start or abort now",
                                    move_func=perform_homing,
                                    move_msg="Homing axes...\n(Ignore position display. Homing is sync operation, therefore blocks UI updates. \nBut E-Stop works and positional display is only shown during dry-runs as feedback anyway.)" if args.dryrun else "Homing axes..."
            ))
        else:
            logger.warning("Will perform homing without user warning because no app was provided")
            home_axes(axes)
    else:
        logger.info(f"No homing required")
        return

def home_axes(axes):
    # The same as home_axes_interactively, but to be used by the worker threads where async/await and requesting user input is not required
    logger.info(f"Homing axes")

    homeing_required = False

    for axis, motor in axes.items():
        if not motor.is_homed():
            homeing_required = True
            break

    if not homeing_required:
        logger.info("No homing required")
        return

    if axes["Z"].is_homed():
        axes["Z"].move_to(0)
    else:
        axes["Z"].home()

    for axis, motor in axes.items():
        if not motor.is_homed():
            motor.home()

    for axis, motor in axes.items():
        if not motor.is_homed():
            motor.wait_for_home()

        new_position = motor.get_position()
        logger.info(f"   - {axis}: Finished. New Position: {new_position:.5f} ")  


def store_positions(axes):
    # Store all axes and their positions in CURRENT_POSITION
    for axis, motor in axes.items():
        try:
            if (motor.is_moving()):
                motor.wait_for_stop()
            CURRENT_POSITION[axis] = motor.get_position() if axis == "Z" else (motor.get_position() - REFERENCE_POINT[axis])
        except Exception as e:
            logger.error(f"{axis}-Axis: Cannot store position due to error reading the position: {e}. Resetting motors.")
            axes = selfheal_axes()
            store_positions(axes)

def retry_movement(axes, faulty_axis, position):
    # If a motor deviates from its expected position after moving beyond a narrow threshold, we home it and try again

    logger.info(f"Retrying movement of axis {faulty_axis}...")
    if faulty_axis != "Z":
        # Move Z axis out of the way
        z_position = axes["Z"].get_position()
        move(axes, {"Z": 0})

    # Homing and retry movement
    try:
        home_axes({faulty_axis: axes[faulty_axis]})
    except Exception as e:
        logger.error(f"Error during homing of axis {faulty_axis}: {e}. Re-initializing axes.")
        axes = selfheal_axes()
        retry_movement(axes, faulty_axis, position)

    move(axes, {faulty_axis: position}, ignore_divergence=True)

    if faulty_axis != "Z":
        # Return Z axis to original position
        move(axes, {"Z": z_position})

def move(axes, movements, ignore_divergence=False, lift_z=True, overwrite=False, relative_movement=True):
    # Instructs motors to move according to the movements variable, a dictionary of axes and the targeted positions (e.g. "X":-2.0) in mm and relative to the REFERENCE_POINT if relative_movement is True

    if not (ALLOW_MOVEMENT or overwrite):
        return

    if movements is None or not isinstance(movements, dict) or len(movements) == 0:
        logger.error("No valid movements provided")
        return

    overview = ' and '.join([f"{axis} to {position:.3f}mm" for axis, position in movements.items()])
    start_time = time.time()
    logger.debug(f"Moving {overview} at {getTime()}")

    try:
        # Move Z axis out of the way
        if ("Z" in axes and "Z" not in movements and lift_z):
            axes["Z"].move_to(BOUNDARIES["Z"]["UP"])
            if (axes["Z"].is_moving()):
                axes["Z"].wait_for_stop()

        axis_results = {}
        for axis, position in movements.items():

            relative_movement_axis = True if (relative_movement and axis != "Z") else False

            if not isinstance(axis, str):
                logger.error(f"Invalid movement {movements}:\n Axis {axis} must be a string")
                stop_event.set()

            if not isinstance(position, (int, float)):
                logger.error(f"Invalid movement {movements}:\n Position {position} must be a number")
                stop_event.set()

            if position >= max_travel:
                logger.error(f"Invalid movement {movements}:\n Position {position} is larger than {max_travel}mm")
                stop_event.set()

            if axis not in axes or not axes[axis].is_opened():
                logger.error(f"Invalid movement {movements}:\n Axis {axis} is unknown")
                stop_event.set()    

            if not isinstance(axes[axis], Thorlabs.kinesis.KinesisMotor) and not args.dryrun:
                logger.error(f"Invalid movement {movements}:\n Axis {axis} does not reference a valid motor")
                stop_event.set()

            if (axes[axis].is_moving()):
                logger.info(f"   - Waiting for {axis} to finish their prior movement ({getTime()})")
                axes[axis].wait_for_stop()
                logger.info(f"   - Axis {axis} finshed prior movement at {getTime()}. Executing new move command now...")

            if relative_movement_axis:
                axes[axis].move_to(position + REFERENCE_POINT[axis])

            else:
                logger.debug(f"Moving {axis} via absolute values! (position: {position:.3f}mm, relative movement axis: {relative_movement_axis})")
                axes[axis].move_to(position)

            if (axes[axis].is_moving()):
                axes[axis].wait_for_stop()

            new_position = (axes[axis].get_position() - REFERENCE_POINT[axis]) if relative_movement_axis else axes[axis].get_position()
            divergence = abs(position - new_position)
            axis_results[axis] = (new_position, divergence)

            if (divergence >= 0.01 and not ignore_divergence):
                logger.error(f"Deviation detected! Axis {axis} finished at position {new_position:.5f}, but should have been at {position:.5f}. Divergence >= 0.01mm. Homing and trying again...")

                retry_movement(axes, axis, position)
                new_position = (axes[axis].get_position() - REFERENCE_POINT[axis]) if relative_movement_axis else axes[axis].get_position()
                divergence = abs(position - new_position)

                if (divergence >= 0.01):
                    logger.error(f"Deviation detected! Axis {axis} finished at position {new_position:.5f}, but should have been at {position:.5f}. Aborting at {getTime()} as homing did not fix the issue...")
                    stop_event.set()

            if (axes[axis].is_moving()):
                axes[axis].wait_for_stop()

        # Return Z axis to lower position
        if ("Z" in axes and "Z" not in movements and lift_z):
            axes["Z"].move_to(BOUNDARIES["Z"]["DOWN"])
            if (axes["Z"].is_moving()):
                axes["Z"].wait_for_stop()

        logger.info(f"Moved for {time.time() - start_time:.2f}s | " + " | ".join(f"{axis} -> {axis_results[axis][0]:.3f}\t(div: +-{axis_results[axis][1]:.5f}mm)" for axis in movements))
    
    except Exception as e:
        logger.error(f"Error during movement of {overview}: {e}. Re-initializing axes.")
        axes = selfheal_axes()
        move(axes, movements, ignore_divergence=ignore_divergence, lift_z=lift_z, overwrite=True, relative_movement=relative_movement)
        return


def jog(axes):
    # While move() handles hardware interactions, jog() handles the logic of selecting the next position to move to according to the scan pattern and returns True if the scan is finished

    global DIRECTION
    global POS_COUNTER
    global TRIES_LEFT_PER_POSITION, FAULT_VOLTAGE, FAULT_VOLTAGE_START_AT_STEP, VARIABLE_STATE, TARGET

    # Reset values that are position dependent
    TARGET.number_of_unparseables_at_position_and_voltage = 0
    TARGET.number_of_unparseables_at_position_and_voltage_in_a_row = 0
    TARGET.number_of_recovery_attempts_at_position_and_voltage = 0
    TRIES_LEFT_PER_POSITION = TRIES_PER_POSITION
    FAULT_VOLTAGE = FAULT_VOLTAGE_START
    FAULT_VOLTAGE_START_AT_STEP = FAULT_VOLTAGE_START

    if not CS.selfheal():
        logger.info("ChipShouter selftest returned negative. Self-heal concluded. Repeating the current position.")
        return False

    CS.request_disable("jogging")

    if VARIABLE_STATE != 2 and (VARIABLE_HIGH_TIME or VARIABLE_VOLTAGE) and TRIES_PER_POSITION >= 12:
        logger.error("Although we are done with this position, VARIABLE_STATE is not 2.")
    VARIABLE_STATE = 0

    try:
        POS_COUNTER += 1
        FAULT_VOLTAGE_START_AT_STEP = FAULT_VOLTAGE_START

        if (CURRENT_POSITION["X"] == None):
            store_positions(axes)

        # Select new position within the boundaries
        if (
            (DIRECTION == "right"   and CURRENT_POSITION["X"] - STEP_SIZE < BOUNDARIES["X"]["RIGHT"]) or
            (DIRECTION == "left"    and CURRENT_POSITION["X"] + STEP_SIZE > BOUNDARIES["X"]["LEFT"])
        ):
            if CURRENT_POSITION["Y"] - STEP_SIZE < BOUNDARIES["Y"]["DOWN"]:
                # Scan is finished
                logger.info(f"Scan finished at {getTime()}. Current position: {CURRENT_POSITION['X']:.3f}mm (X), {CURRENT_POSITION['Y']:.3f}mm (Y)")
                return True
            else:
                # Continue in next row
                if DIRECTION    == "right":
                    DIRECTION = "left"
                    move(axes, {"Y": CURRENT_POSITION["Y"] - STEP_SIZE})

                elif DIRECTION  == "left":
                    DIRECTION = "right"
                    move(axes, {"Y": CURRENT_POSITION["Y"] - STEP_SIZE})

        else:
            if DIRECTION == "right":
                move(axes, {"X": CURRENT_POSITION["X"] - STEP_SIZE})
            elif DIRECTION == "left":
                move(axes, {"X": CURRENT_POSITION["X"] + STEP_SIZE})

        store_positions(axes)
    except Exception as e:
        logger.error(f"Jogging failed: {e}")
    finally:
        CS.release_disable("jogging")

def logBoundaries():
    # This function is invoked as part of setting up the motors and logs the currently set boundaries
    logger.info(f"Step-size is: {STEP_SIZE:.3f} mm, Boundaries are:")
    logger.info(f" - X: {BOUNDARIES['X']['LEFT']:.5f} mm (Left), {BOUNDARIES['X']['RIGHT']:.5f} mm (Right), {REFERENCE_POINT['X']:.5f} mm (Reference)")
    logger.info(f" - Y: {BOUNDARIES['Y']['UP']:.5f} mm (Up), {BOUNDARIES['Y']['DOWN']:.5f} mm (Down), {REFERENCE_POINT['Y']:.5f} mm (Reference)")
    logger.info(f" - Z: {BOUNDARIES['Z']['UP']:.5f} mm (Up), {BOUNDARIES['Z']['DOWN']:.5f} mm (Down)")
    
async def setBoundaries(axes, app):
    # Part of the setup process. Defines the boundaries of our scan pattern through user interaction or loading them from previous runs.

    global BOUNDARIES, REFERENCE_POINT

    async def setReferencePoint(axes):
        global REFERENCE_POINT

        await app.push_screen_wait(JogInteractively(axes, "Please move the probe on the X and Y axes such that it is at the reference point, e.g., the TOP-LEFT corner of the chip bracket. This is such that coordinates share a common origin even when the target is moved."))

        REFERENCE_POINT["X"] = axes["X"].get_position()
        REFERENCE_POINT["Y"] = axes["Y"].get_position()        

        assert(REFERENCE_POINT["X"] is not None and REFERENCE_POINT["Y"] is not None), "Reference point for X and Y axes must be set before the Boundaries can be set."

        store_positions(axes)

    if not axes:
        logger.error("No axes provided to set boundaries")
        stop_event.set()
    if app is None:
        logger.error("No Textual app currently running. Cannot set boundaries.")
        stop_event.set()

    boundaries_loaded = False if BOUNDARIES["X"]["LEFT"] is None else True

    if not boundaries_loaded and os.path.exists(BOUNDARIES_FILE):

        if args.quickdebug:
            result = True
        else:
            result = await app.push_screen_wait(YesNoScreen("Do you want to load the boundaries from the last run?"))
        if result:
            try:
                with open(BOUNDARIES_FILE, "rb") as f:
                    boundaries = pickle.load(f)
                    BOUNDARIES = boundaries["BOUNDARIES"]
                    REFERENCE_POINT = boundaries["REFERENCE_POINT"]
                logger.info(f"Loaded boundaries from {BOUNDARIES_FILE}")
                
                logBoundaries()
                boundaries_loaded = True
            except Exception as e:
                logger.error(f"Failed to load boundaries: {e}")

            if args.quickdebug:
                target_moved = False
            else:
                target_moved = await app.push_screen_wait(LoadBoundariesDisplay(axes))

    
    if boundaries_loaded and not target_moved:
        logger.info("Using previously set boundaries and reference point.")

    else:
        await setReferencePoint(axes)
        
        if not boundaries_loaded:
            await app.push_screen_wait(JogInteractively(axes, "Please move the probe on all axes such that it is LOWERED and in the TOP-LEFT corner of the chip."))

            BOUNDARIES["X"]["LEFT"] = axes["X"].get_position() - REFERENCE_POINT["X"]
            BOUNDARIES["Y"]["UP"] = axes["Y"].get_position() - REFERENCE_POINT["Y"]
            BOUNDARIES["Z"]["DOWN"] = axes["Z"].get_position()

            BOUNDARIES["Z"]["UP"] = BOUNDARIES["Z"]["DOWN"] - 0.5

            await app.push_screen_wait(JogInteractively({"X": axes["X"]}, msg="Please move the probe on the X axis such that it is at the RIGHT edge of the chip."))
            BOUNDARIES["X"]["RIGHT"] = axes["X"].get_position()  - REFERENCE_POINT["X"]

            await app.push_screen_wait(JogInteractively({"Y": axes["Y"]}, msg="Please move the probe on the Y axis such that it is at the LOWER edge of the chip (looking from above)."))
            BOUNDARIES["Y"]["DOWN"] = axes["Y"].get_position() - REFERENCE_POINT["Y"]

        elif target_moved:
            if await app.push_screen_wait(YesNoScreen("Do you want to set a new Z-Axis boundary?")):
                await app.push_screen_wait(JogInteractively(axes, "Please move the Z-Axis such that it is LOWERED on the chip."))
                BOUNDARIES["Z"]["DOWN"] = axes["Z"].get_position()
                BOUNDARIES["Z"]["UP"] = BOUNDARIES["Z"]["DOWN"] - 0.5

            else:
                logger.info("Using previously set Z-Axis boundaries per user request.")

    logBoundaries()

    # Run along the to-scan area to check collisions early / before starting the hour-long tests
    if args.quickdebug or not await app.push_screen_wait(YesNoScreen("Do you want to move along the boundaries to verify they are set correct?")):
        logger.warning("Skipping boundary verification as requested by user.")

    else:
        msg = "To verify the area that shall be scanned, the probe will be moved along all edges of the scanning area in two passes.\nBe prepared to pull the plug on the motors to prevent collision with the chip!"
        msg_firstpass = "1st pass with the Z-axis out of the way. Press Enter to start."
        msg_secondpass = "2nd pass with the Z-axis in the lowered position. Press Enter to start."

        def move_along_boundary_one(self, axes):
            self.running = True
            move(axes, {"Z": max(BOUNDARIES["Z"]["UP"] - 15, 0)})
            move(axes, {"X": BOUNDARIES["X"]["LEFT"], "Y": BOUNDARIES["Y"]["UP"]}, lift_z=False)                  # |`` <-
            move(axes, {"X": (BOUNDARIES["X"]["RIGHT"] + (BOUNDARIES["X"]["RIGHT"] % STEP_SIZE))}, lift_z=False)  #  -> ``|
            move(axes, {"Y": (BOUNDARIES["Y"]["DOWN"]  + (BOUNDARIES["Y"]["DOWN"] % STEP_SIZE))}, lift_z=False)   #  -> __|
            move(axes, {"X": BOUNDARIES["X"]["LEFT"]}, lift_z=False)                                              # |__ <-
            move(axes, {"Y": BOUNDARIES["Y"]["UP"]}, lift_z=False)                                                # |`` <-
            self.running = False
            self.dismiss()

        def move_along_boundary_two(self, axes):
            self.running = True
            move(axes, {"Z": BOUNDARIES["Z"]["DOWN"]})
            move(axes, {"X": BOUNDARIES["X"]["LEFT"], "Y": BOUNDARIES["Y"]["UP"]}, lift_z=False)                  # |`` <-
            move(axes, {"X": (BOUNDARIES["X"]["RIGHT"] + (BOUNDARIES["X"]["RIGHT"] % STEP_SIZE))}, lift_z=False)  #  -> ``|
            move(axes, {"Y": (BOUNDARIES["Y"]["DOWN"]  + (BOUNDARIES["Y"]["DOWN"] % STEP_SIZE))}, lift_z=False)   #  -> __|
            move(axes, {"X": BOUNDARIES["X"]["LEFT"]}, lift_z=False)                                              # |__ <-
            move(axes, {"Y": BOUNDARIES["Y"]["UP"]}, lift_z=False)                                                # |`` <-
            self.running = False
            self.dismiss()

        await app.push_screen_wait(MoveInteractively(axes, msg + "\n" + msg_firstpass, move_along_boundary_one))

        pos_x = axes["X"].get_position() - REFERENCE_POINT["X"]
        pos_y = axes["Y"].get_position() - REFERENCE_POINT["Y"]

        divergence_x = abs(BOUNDARIES["X"]["LEFT"]  - pos_x)
        divergence_y = abs(BOUNDARIES["Y"]["UP"]    - pos_y)

        if (divergence_x >= 0.01):
            logger.error(f"Deviation detected on validating boundaries! Axis X finished at position {pos_x:.5f}, but should have been at {BOUNDARIES["X"]["LEFT"]:.5f}. Aborting at {getTime()}")
            stop_event.set()
            return

        if (divergence_y >= 0.01):
            logger.error(f"Deviation detected on validating boundaries! Axis Y finished at position {pos_y:.5f}, but should have been at {BOUNDARIES["Y"]["UP"]:.5f}. Aborting at {getTime()}")
            stop_event.set()
            return

        await app.push_screen_wait(MoveInteractively(axes, msg + "\n" + msg_secondpass, move_along_boundary_two))

        pos_x = axes["X"].get_position() - REFERENCE_POINT["X"]
        pos_y = axes["Y"].get_position() - REFERENCE_POINT["Y"]

        divergence_x = abs(BOUNDARIES["X"]["LEFT"]  - pos_x)
        divergence_y = abs(BOUNDARIES["Y"]["UP"]    - pos_y)
        divergence_z = abs(BOUNDARIES["Z"]["DOWN"]  - axes["Z"].get_position())

        if (divergence_x >= 0.01):
            logger.error(f"Deviation detected on validating boundaries! Axis X finished the second run at position {pos_x:.5f}, but should have been at {BOUNDARIES["X"]["LEFT"]:.5f}. Aborting at {getTime()}")
            stop_event.set()
            return

        if (divergence_y >= 0.01):
            logger.error(f"Deviation detected on validating boundaries! Axis Y finished the second run at position {pos_y:.5f}, but should have been at {BOUNDARIES["Y"]["UP"]:.5f}. Aborting at {getTime()}")
            stop_event.set()
            return

        if (divergence_z >= 0.01):
            logger.error(f"Deviation detected on validating boundaries! Axis Z finished the second run at position {axes["Z"].get_position():.5f}, but should have been at {BOUNDARIES["Z"]["DOWN"]:.5f}. Aborting at {getTime()}")
            stop_event.set()
            return
    
        move(axes, {"Z": BOUNDARIES["Z"]["UP"]})
    
    with open(BOUNDARIES_FILE, "wb") as f:
        boundaries = {
            "BOUNDARIES": BOUNDARIES,
            "REFERENCE_POINT": REFERENCE_POINT,
        }
        pickle.dump(boundaries, f)
    logger.info(f"Successfully verified the motor boundaries and saved them to {BOUNDARIES_FILE}")   
    
    
""" 
### Communication-related functions
"""
def onSignature(payload_str, sig_params): 
    global TRIES_LEFT_PER_POSITION, TRIES_LEFT_PER_POSITION_AND_TIME
    global CURRENT_PROGRESS, TOTAL_PROGRESS
    global AXES, CS, TARGET
    global LOOPING_COUNTER_UNPARSEABLE_SIGNATURE
    global FAULT_VOLTAGE, FAULT_VOLTAGE_START_AT_STEP, VARIABLE_STATE
    global SIG_COUNTER, CS_DISABLED_FOR_COUNTER
    global CONFIRMED_FAULTS, SIGNATURES_PARAMS

    SIG_COUNTER += 1

    if not CS.enabled:
        logger.debug(f"Skipping signature processing as faulting is currently not allowed. disabled_for: {CS_DISABLED_FOR_COUNTER}")
        CS_DISABLED_FOR_COUNTER += 1
        if CS_DISABLED_FOR_COUNTER > 200:
            logger.error(f"CS was disabled for {CS_DISABLED_FOR_COUNTER} signatures. Assuming this is an error. Re-enabling it.")
            CS.release_disable("CS_disabeled_timeout")
        return

    CS_DISABLED_FOR_COUNTER = 0
    TARGET.number_of_signatures += 1
    CURRENT_PROGRESS += 1
    if not ALLOW_MOVEMENT:
        TOTAL_PROGRESS += 1

    if payload_str != VALID_SIGNATURE:

        if len(payload_str) == len(VALID_SIGNATURE):
            logger.info(f"Success: Found an invalid signature!")
            logger.info(f"- {payload_str}")
        else:
            logger.info(f"Success: Found an invalid signature (non-equal length)!")
            logger.info(f"- {payload_str}")

        store_positions(AXES)
               
        CONFIRMED_FAULTS.append({
            "signature": payload_str,
            "signature_str": payload_str.strip(),
            **(sig_params or {}),
        })

        logger.info(f"- Current position: {sig_params.get("position", {'X':-8})['X']:.3f}mm (X), {sig_params.get("position", {'Y':-8})['Y']:.3f}mm (Y), {sig_params.get("position", {'Z':-8})['Z']:.3f}mm (Z) | Measured: {sig_params.get("voltage_measured", -7)}V")

        SIGNATURES_PARAMS.append({
            "result": "faulted",
            **(sig_params or {}),
        })

    else:
        SIGNATURES_PARAMS.append({
            "result": "valid_signature",
            **(sig_params or {}),
        })

    if (VARIABLE_HIGH_TIME or VARIABLE_VOLTAGE) and TRIES_PER_POSITION >= 12:
        
        if VARIABLE_STATE == 0 and (TRIES_LEFT_PER_POSITION / TRIES_PER_POSITION) <= 0.66:

            logger.info("First 30% at position done. Adjusting voltage and/or hightime.")
            
            if VARIABLE_HIGH_TIME:
                high_time_start = sum(1 for x in FAULT_PATTERN_START if x == 1) * FAULT_PATTERN_INCREMENTS

                if high_time_start >= MAX_HIGH_TIME_ns:
                    new_high_time = high_time_start - FAULT_PATTERN_INCREMENTS
                else:
                    new_high_time = min(high_time_start + FAULT_PATTERN_INCREMENTS, MAX_HIGH_TIME_ns)
                CS.change(timeHigh_ns=new_high_time)

            if VARIABLE_VOLTAGE:
                if FAULT_VOLTAGE_START_AT_STEP >= MAX_VOLTAGE - FAULT_VOLTAGE_INCREMENTS:
                    new_voltage = FAULT_VOLTAGE_START_AT_STEP - FAULT_VOLTAGE_INCREMENTS
                else:
                    new_voltage = min(FAULT_VOLTAGE_START_AT_STEP + FAULT_VOLTAGE_INCREMENTS, MAX_VOLTAGE)
                CS.change(voltage=new_voltage)

            VARIABLE_STATE = 1

        elif VARIABLE_STATE == 1 and (TRIES_LEFT_PER_POSITION / TRIES_PER_POSITION) <= 0.33:

            logger.info("First 60% at position done. Adjusting voltage and/or hightime.")

            if VARIABLE_HIGH_TIME:
                high_time_start = sum(1 for x in FAULT_PATTERN_START if x == 1) * FAULT_PATTERN_INCREMENTS

                if high_time_start >= MAX_HIGH_TIME_ns:
                    new_high_time = high_time_start - (2 * FAULT_PATTERN_INCREMENTS)
                else:
                    new_high_time = max(high_time_start - FAULT_PATTERN_INCREMENTS, MIN_HIGH_TIME_ns)
                CS.change(timeHigh_ns=new_high_time)

            if VARIABLE_VOLTAGE:
                if FAULT_VOLTAGE_START_AT_STEP >= MAX_VOLTAGE:
                    new_voltage = FAULT_VOLTAGE_START_AT_STEP - (2 * FAULT_VOLTAGE_INCREMENTS)
                else:
                    new_voltage = max(FAULT_VOLTAGE_START_AT_STEP - FAULT_VOLTAGE_INCREMENTS, MIN_VOLTAGE)
                CS.change(voltage=new_voltage)

            VARIABLE_STATE = 2
        

    if TRIES_LEFT_PER_POSITION <= 1 and ALLOW_MOVEMENT:

        logger.debug("Position done. Resetting variables and moving to next position.")

        if VARIABLE_DELAY:
            raise NotImplementedError("Variable delay is not yet implemented. It would add many millions of zeros to the pattern, which is probably not supported by the ChipShouter. Also, we already vary the delay through varying the hightime")
            raise NotImplementedError("Remember, variable voltage and pattern use the TRIES_LEFT_PER_POSITION. If you implement variable delay here, you should change that behavior such that different voltages and patterns are tried for every different delay")
            TRIES_LEFT_PER_POSITION_AND_TIME = NO_OF_TRIES_PER_DELAY_INCREMENT
            CS.pat_wave = FAULT_PATTERN

        return jog(AXES)
    
    else:
        TRIES_LEFT_PER_POSITION -= 1

        if VARIABLE_DELAY:
            raise NotImplementedError(f"Variable delay is not yet implemented. It would add many millions of zeros to the pattern, which is probably not supported by the ChipShouter. Also, we already vary the delay through varying the hightime")
            if TRIES_LEFT_PER_POSITION_AND_TIME <= 1:
                TRIES_LEFT_PER_POSITION_AND_TIME = NO_OF_TRIES_PER_DELAY_INCREMENT
                CS.pat_wave = [0] * int(DELAY_INCREMENT_in_ms * 1_000_000 / MIN_HIGH_TIME_ns) + CS.pat_wave # One zero adds 20ns delay to the signal, I think
            else:
                TRIES_LEFT_PER_POSITION_AND_TIME -= 1

        return False

def onMessage(payload_str, sig_params):
    if binascii.unhexlify(payload_str) != REAL_MSG:
        logger.error(f"Received message does not match expected message:\n {payload_str}")

def onDigest(payload_str, sig_params):
    if payload_str != REAL_DIGEST:
        logger.error(f"Received digest does not match expected digest:\n {payload_str}")

def onPrivKey_n(payload_str, sig_params):
    if REAL_SIGN_PARAMS["PrivKey"]["n"] != payload_str:
        logger.error(f"Invalid PrivKey_n:\n {payload_str}")

def onPrivKey_d(payload_str, sig_params):
    if REAL_SIGN_PARAMS["PrivKey"]["d"] != payload_str:
        logger.error(f"Invalid PrivKey_n:\n {payload_str}")

def onPubKey_n(payload_str, sig_params):
    if REAL_SIGN_PARAMS["PubKey"]["n"] != payload_str:
        logger.error(f"Invalid PubKey_n:\n {payload_str}")

def onPubKey_e(payload_str, sig_params):
    if REAL_SIGN_PARAMS["PubKey"]["e"] != payload_str:
        logger.error(f"Invalid PubKey_e:\n {payload_str}")

def onTimings(payload_str, sig_params):
    global PAST_TIMINGS
    try:
        parts = str(payload_str).strip().split(",")
        if len(parts) != 3:
            logger.error(f"Invalid timing payload: {payload_str}")
            return

        # Calculate and store timing statistics for later evaluation
        between_trigger_and_signGen_ms = int(parts[2]) - int(parts[0]) # CURRENT_TIMING["after_sign_ms"] - CURRENT_TIMING["after_trigger_ms"]
        trigger_duration_ns = int(parts[1])

        PAST_TIMINGS["between_trigger_and_signGen_ms"].append(between_trigger_and_signGen_ms)
        PAST_TIMINGS["trigger_duration_ns"].append(trigger_duration_ns)

        # Store timing statistics in the last SIGNATURES_PARAMS entry if available
        if SIGNATURES_PARAMS and between_trigger_and_signGen_ms and trigger_duration_ns:
            SIGNATURES_PARAMS[-1]["between_trigger_and_signGen_ms"] = between_trigger_and_signGen_ms
            SIGNATURES_PARAMS[-1]["trigger_duration_ns"] = trigger_duration_ns

    except ValueError as e:
        logger.error(f"Failed to parse timing payload: {payload_str}\n{e}")

def onPause(payload_str, sig_params):
    # CS.trigger_safe # Allow ChipShouter to do self-tests. Not necessary as we do not use the hardware trigger
    logger.info("Target initiated a short break.")
    export_params()
    save_checkpoint()

def onAlarm(payload_str, sig_params):
    global CONFIRMED_ALARMS
    if payload_str is None:
        logger.warning("Target indicated that an alarm was triggered, but payload_str is None")
        alarms = []
    
    if payload_str.strip() == "":
        logger.warning("Target indicated that an alarm was triggered, but payload_str is empty")
        alarms = []

    else:
        logger.debug(f"Target indicated that an alarm was triggered: {payload_str}")
        try:
            alarms = [alarm.strip() for alarm in payload_str.split(",")]
        except Exception as e:
            logger.warning(f"Could not split alarm string {payload_str} based on ','. Using the whole string. Error: {e}")
            alarms = [payload_str.strip()]

    if len(alarms) >= 1 and "TEST_ALARM" in alarms[0]:
        logger.info("Received TEST_ALARM. Ignoring as this is just a test alarm.")
    else:
        CONFIRMED_ALARMS.append({
            "alarms": alarms,
            **(sig_params or {}),
        })

        

KEYWORD_HANDLERS = {
    "Signature:": 
    {
        "TARGET": onSignature,
    },
    "Message:":
    {
        "TARGET": onMessage,
    },
    "Digest:":
    {
        "TARGET": onDigest,
    },
    "PrivKey_n:":
    {
        "TARGET": onPrivKey_n,
    },
    "PrivKey_d:":
    {
        "TARGET": onPrivKey_d,
    },
    "PubKey_n:":
    {
        "TARGET": onPubKey_n,
    },
    "PubKey_e:":
    {
        "TARGET": onPubKey_e,
    },
    "Timings:":
    {
        "TARGET": onTimings,
    },
    "Pause:":
    {
        "TARGET": onPause,
    },
    "Alarm:":
    {
        "TARGET": onAlarm,
    },
}

""" 
### Meta functions required for setup
"""

def verifyParameters():
    assert(CHIPSHOUTER_PORT != TARGET_PORT), "ChipShouter and TC49 must not use the same port"
    assert(BOUNDARIES["X"]["LEFT"] > BOUNDARIES["X"]["RIGHT"]), "X_BOUNDARY_LEFT must be smaller than X_BOUNDARY_RIGHT"
    assert(BOUNDARIES["Y"]["UP"] > BOUNDARIES["Y"]["DOWN"]), "Y_BOUNDARY_UP must be smaller than Y_BOUNDARY_DOWN"
    assert(BOUNDARIES["Z"]["UP"] < BOUNDARIES["Z"]["DOWN"]), "Z_BOUNDARY_UP must be larger than Z_BOUNDARY_DOWN"
    assert(STEP_SIZE > 0), "STEP_SIZE must be larger than 0"
    assert(BOUNDARIES["X"]["LEFT"]  - BOUNDARIES["X"]["RIGHT"]  >= STEP_SIZE), "X-Axis: Distance between boundaries is smaller than the step-size"
    assert(BOUNDARIES["Y"]["UP"]    - BOUNDARIES["Y"]["DOWN"]   >= STEP_SIZE), "Y-Axis: Distance between boundaries is smaller than the step-size"
    assert(DIRECTION in ["right", "left"]), "DIRECTION must be either 'right' or 'left'"
    assert(TRIES_PER_POSITION > 0), "TRIES_PER_POSITION must be larger than 0"

    assert("0d0a" not in VALID_SIGNATURE.lower()), "VALID_SIGNATURE must not contain the sequence '0d0a' as this is used to detect the end of a line in the serial communication"
    
    # Calculate RSA PKCS#1 v1.5 signature myself and check that it matches VALID_SIGNATURE (PKCS#1 v1.5 is deterministic)
    hash = SHA256.new(data=REAL_MSG)
    assert hash.hexdigest() == REAL_DIGEST, "Calculated hash does not match REAL_DIGEST"

    key_pub = RSA.construct(
        (int(REAL_SIGN_PARAMS["PubKey"]["n"], 16),
         int(REAL_SIGN_PARAMS["PubKey"]["e"], 16)
        ), consistency_check=True)
    key_priv = RSA.construct(
        (int(REAL_SIGN_PARAMS["PrivKey"]["n"], 16),
         int(REAL_SIGN_PARAMS["PubKey"]["e"] , 16),
         int(REAL_SIGN_PARAMS["PrivKey"]["d"], 16)
        ), consistency_check=True)

    signature = signalgo.new(key_priv).sign(hash)
    sig_hex = binascii.hexlify(signature).decode().lower().strip()
    assert sig_hex == VALID_SIGNATURE, "Failed trying to replicate the given Signature"

    # Disabled as PKCS#1 v1.5 is deterministic
    # try:
    #     signalgo.new(key_pub).verify(REAL_DIGEST,VALID_SIGNATURE)
    # except Exception as e:
    #     raise Exception("Failed to verify the given signature with the given digest and public key: {e}")
        
    # wrong_key = RSA.generate(2048, e=65537)
    # try:
    #     signalgo.new(wrong_key).verify(REAL_DIGEST,VALID_SIGNATURE)
    # except Exception as e:
    #     logger.info(f"fail{e}")
    # else:
    #     raise Exception("The given signature verified correctly with the given digest and a random public key. Verification methodology is flawed!")

    if HEADER_FILE_PATH is not None:
        try:
            with open(HEADER_FILE_PATH, "r") as f:
                header_lines = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            raise Exception(f"Could not read header file {HEADER_FILE_PATH}. This file contains the targets banner and is used together with LEN_HEADER_STATIC_PART_TOP and LEN_HEADER_STATIC_PART_BOTTOM do detect a target reset in progress. Error was: {e}")

        if len(header_lines) < LEN_HEADER_STATIC_PART_TOP + LEN_HEADER_STATIC_PART_BOTTOM:
            raise Exception(f"Header file {HEADER_FILE_PATH} does not contain enough lines. Expected at least {LEN_HEADER_STATIC_PART_TOP + LEN_HEADER_STATIC_PART_BOTTOM}, but got {len(header_lines)}. Please check that LEN_HEADER_STATIC_PART_TOP and LEN_HEADER_STATIC_PART_BOTTOM are set correctly.")
    else:
        logger.warning("No header file specified. This means that the target reset detection will not work. Please set HEADER_FILE_PATH to a valid file path containing the targets banner.")

    logger.info("All parameters successfully verified")
    return

def calculate_variable_delay_profile():
    MIN_INCREMENT_IN_PERCENT = 1
    min_increment_ms = EXPECTED_DURATION_SIG_GEN_ms * MIN_INCREMENT_IN_PERCENT / 100

    tries_per_increment = MIN_TRIES_PER_POSITION_AND_TIMING
    while True:
        num_increments = TRIES_PER_POSITION // tries_per_increment
        if num_increments < 1:
            num_increments = 1
            tries_per_increment = TRIES_PER_POSITION  # all tries in one increment

        increment_ms = EXPECTED_DURATION_SIG_GEN_ms / num_increments

        if increment_ms >= min_increment_ms or tries_per_increment >= TRIES_PER_POSITION:
            break
        tries_per_increment += 1

    return increment_ms, tries_per_increment

def find_tty_path(serial_number):

    dict_expected = True

    if not isinstance(serial_number, dict):
        dict_expected = False
        serial_number = {serial_number: None}

    for port in serial.tools.list_ports.comports():
        for sn, target_name in serial_number.items():
            if port.serial_number == sn:
                if dict_expected:
                    logger.info(f"Found {port.device} for serial number {sn}. Assuming Target to be {target_name}")
                    return port.device, target_name
                else:
                    logger.info(f"Found {port.device} for serial number {sn}")
                    return port.device
            
    stop_event.set()

    if dict_expected:
        logger.error(f"Could not find serial port for serial numbers {serial_number}. Available ports: {[port.device for port in serial.tools.list_ports.comports()]}")
        return None, None
    else:
        logger.error(f"Could not find serial port for serial number {serial_number}. Available ports: {[port.device for port in serial.tools.list_ports.comports()]}")
        return None
    
""" 
### Classes that store states and include hardware-related functions for the target and for the ChipShouter
"""

class OperationalState(Enum):
    NORMAL = auto()
    FIRST_UNPARSEABLE = auto()
    CS_DISABLED = auto()
    STARTED_FIRST_RESET = auto()
    IN_FIRST_RESET = auto()
    AFTER_FIRST_RESET = auto()
    STARTED_SECOND_RESET = auto()
    IN_SECOND_RESET = auto()
    AFTER_SECOND_RESET = auto()
    TRYING_BAUDRATES = auto()

class SerialTarget:
    def __init__(self, port, baudrate, device, event_queue, stop_event):
        global CS
        self.port = port
        self.baudrate = baudrate
        self.alternative_baudrate = ALTERNATIVE_BAUDRATE
        self.device = device
        self.ser = None
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.cs = CS
        
        # Target state management
        self.target_state = OperationalState.NORMAL
        self.time_last_reset = None
        
        # Header file configuration
        self.banner_provided = False
        self.header_first_part = set()
        self.header_last_part = set()
        self._load_header_config()
        
        # Serial communication state
        self.buffer = None
        self.number_of_signatures = 0
        self.number_of_unparseables = 0
        self.number_of_unparseables_at_position_and_voltage = 0
        self.number_of_unparseables_at_position_and_voltage_in_a_row = 0
        self.number_of_empty = 0
        self.number_of_sr_errors = 0
        self.number_of_recovery_attempts_at_position_and_voltage = 0
        
        # Message parsing configuration
        self.signature_byte_length = len(binascii.unhexlify(VALID_SIGNATURE))
        self.max_read_length = self.signature_byte_length * 2
        
    def _load_header_config(self):
        """Load header configuration from file if available."""
        try:
            with open(HEADER_FILE_PATH, "r") as f:
                header_lines = [line.strip() for line in f.readlines() if line.strip()]
            
            self.banner_provided = True
            self.header_first_part = set(header_lines[:LEN_HEADER_STATIC_PART_TOP])
            self.header_last_part = set(header_lines[-LEN_HEADER_STATIC_PART_BOTTOM:])
        except Exception:
            pass  # Already handled in verifyParameters()
    
    def _create_serial_connection(self, port=None, baudrate=None):
        """Create and return serial connection or dummy target."""
        if args.dryrun and not args.realtarget:
            global DUMMY_TARGET
            self.ser = DUMMY_TARGET
        else:
            self.ser = serial.Serial(
                port if port else self.port, 
                baudrate if baudrate else self.baudrate, 
                timeout=(EXPECTED_DURATION_SIG_GEN_ms / 1000 * 2)
            )
    
    def _is_parseable_string(self, payload_str, allowed_length, allowed_chars):
        """Check if a string is parseable based on length and character constraints."""
        invalid_chars = sum(1 for c in payload_str if c not in allowed_chars)
        length_diff = abs(len(payload_str) - allowed_length)
        
        max_length_diff = max(1, allowed_length * 0.1)
        max_invalid_chars = max(1, len(payload_str) * 0.4)
        
        return not (length_diff > max_length_diff or invalid_chars > max_invalid_chars)
    
    def _is_timings(self, s):
        """Check if string represents timing data."""
        return (len(s.split(",")) == 3 and 
                all(part.strip().isdigit() for part in s.split(",")))
    
    def _is_alarm(self, s):
        """Check if string represents an alarm message."""
        return any(alarm in s for alarm in ALARMS_DEFINED)
    
    def _serial_to_string(self, payload):
        """Convert serial payload to parseable string."""
        parseable_checks = [
            lambda s: s in KEYWORD_HANDLERS,
            # lambda s: self._is_parseable_string(s, len(VALID_SIGNATURE), "0123456789abcdef"), sent as binary data
            lambda s: self._is_timings(s),
            lambda s: self._is_alarm(s),
            lambda s: s in "for 30sec",
            lambda s: self._is_parseable_string(s, len(REAL_MSG), "0123456789abcdef"),
            lambda s: self._is_parseable_string(s, len(REAL_DIGEST), "0123456789abcdef"),
            lambda s: self._is_parseable_string(s, len(REAL_SIGN_PARAMS["PrivKey"]["n"]), "0123456789abcdef"),
            lambda s: self._is_parseable_string(s, len(REAL_SIGN_PARAMS["PrivKey"]["d"]), "0123456789abcdef"),
            lambda s: self._is_parseable_string(s, len(REAL_SIGN_PARAMS["PubKey"]["n"]), "0123456789abcdef"),
            lambda s: self._is_parseable_string(s, len(REAL_SIGN_PARAMS["PubKey"]["e"]), "0123456789abcdef"),
        ]

        if not isinstance(payload, bytes):
            logger.error(f"Received payload of type {type(payload)}. Expected bytes.")
            return False, None
            
        payload_str = ""
        prefix_location = payload.find(PREFIX)

        if prefix_location != -1:  # Message contains prefix, assume signature
            logger.debug(f"Found prefix, assuming signature ({payload[:8]}...)")
            payload = payload[prefix_location + len(PREFIX):]
            
            try:
                payload_str = binascii.hexlify(payload).decode("ascii")
                payload_str = payload_str.rstrip("0d0a").strip()
                return True, payload_str
            except Exception:
                logger.error("Error converting payload to string")
                return False, None
        else:  # No signature prefix
            logger.debug(f"Found no prefix, assuming an encoded string ({payload[:8]}...)")
            
            try:
                payload_str = payload.decode(errors="replace")
                payload_str = payload_str.rstrip("\r\n").strip()
                
                if payload_str != "" and any(check(payload_str) for check in parseable_checks):
                    return True, payload_str
                else:
                    return False, payload_str
            except Exception:
                logger.error("Error converting payload to string")
                return False, None

    def reset(self):
        """Reset the target device."""
        try:
            self.time_last_reset = time.time()

            self.cs.request_disable("target_reset")
            time.sleep(1)

            with target_lock:
                if self.target_state == OperationalState.AFTER_FIRST_RESET:
                    self.target_state = OperationalState.STARTED_SECOND_RESET
                else:
                    self.target_state = OperationalState.STARTED_FIRST_RESET

                logger.debug(f"Reset changed the state to {self.target_state}")           

                if args.dryrun:
                    if args.realtarget:
                        logger.warning("Dry-run with real target. Skipping actual reset command as Arduino is emulated but target is not.")
                        return
                    
                    logger.debug("Trying to reset dummy target")
                    global DUMMY_TARGET
                    DUMMY_TARGET.reset()
                    logger.info("This is a dry-run. Reset dummy target.")

                else:
                    arduino = serial.Serial(ARDUINO_PORT, ARDUINO_BAUDRATE, timeout=10)
                    time.sleep(3)

                    arduino.write("reset\n".encode())
                    res = arduino.readline().decode('utf-8').strip()

                    if SHOW_UART:
                        logger.info(f"ARDUINO | {res}")

                    if res == "reset":
                        logger.info("Arduino reports that it will reset the target now.")
                    else:
                        raise Exception(f"Arduino reported: {res}")

        except Exception as e:
            logger.error(f"Failed to reset target: {e}")
            self.cs.release_disable("target_reset")

    def _handle_reset_state(self, line_str):
        """Handle target reset state detection and management."""
        if (self.target_state == OperationalState.IN_FIRST_RESET or 
            self.target_state == OperationalState.IN_SECOND_RESET):
            
            if self.time_last_reset is None:
                logger.warning("TARGET_STATE indicates a reset but time_last_reset is None. Setting to current time.")
                self.time_last_reset = time.time()

            # Check if reset is over
            reset_complete = (
                (self.banner_provided and line_str.strip() in self.header_last_part) or
                ((time.time() - self.time_last_reset) > MAX_TIME_REQUIRED_FOR_TARGET_RESET_in_s)
            )
            
            if reset_complete:
                self._complete_reset(line_str)
            
            elif not self.banner_provided:
                time.sleep(MAX_TIME_REQUIRED_FOR_TARGET_RESET_in_s)
            
            if SHOW_UART:
                logger.info(f"TARGET | Reset: {line_str}")

            return True
        
        else:
            return False

    def _complete_reset(self, line_str):
        """Complete the reset process and update state."""
        self.time_last_reset = None

        self.target_state = (OperationalState.AFTER_FIRST_RESET if self.target_state == OperationalState.IN_FIRST_RESET 
                                                                else OperationalState.AFTER_SECOND_RESET)

        if "target_reset" in self.cs.disable_requests:
            self.cs.release_disable("target_reset")

        if line_str.strip() in self.header_last_part:
            logger.debug(f"Detected end of reset based on line: {line_str}")

        elif self.target_state != OperationalState.AFTER_SECOND_RESET:
            logger.warning(f"Reset timeout reached. Resetting again...")
            self.target_state = OperationalState.STARTED_SECOND_RESET
            self.reset()

        else:
            logger.warning(f"Reset timeout reached. Continueing anyway...")

    def _detect_target_reset(self, line_str):
        """Detect if target has been reset."""
        if not self.banner_provided or line_str.strip() not in self.header_first_part:
            return False
        
        if self.target_state == OperationalState.STARTED_FIRST_RESET:
            self.target_state = OperationalState.IN_FIRST_RESET
        elif self.target_state == OperationalState.STARTED_SECOND_RESET:
            self.target_state = OperationalState.IN_SECOND_RESET
        else:
            logger.warning(f"Target reset detected without us triggering it! {self.target_state} -> IN_FIRST_RESET")
            self._log_unparseable("reset_detected")
            # if not self.time_last_reset:
            #     self.time_last_reset = time.time()
            # self.reset()
            self.target_state = OperationalState.IN_FIRST_RESET

        logger.debug(f"Detected reset of target based on line: {line_str}")
        if SHOW_UART:
            logger.info(f"TARGET | Reset: {line_str}")
        return True
    
    def _log_unparseable(self, result="unparseable_without_reason"): # undefined
        global SIGNATURES_PARAMS
        sig_params = self._gather_signature_params()
        SIGNATURES_PARAMS.append({
            "result": result,
            **(sig_params or {}),
        })

    def _append_last_param(self, result):
        """Log unexpected reset event."""
        global SIGNATURES_PARAMS
        if len(SIGNATURES_PARAMS) > 0:
            SIGNATURES_PARAMS[-1]["result"] = result
        else:
            logger.warning("Tried to append last parameter but SIGNATURES_PARAMS is empty. This should not happen.")

    def _gather_signature_params(self):
        voltage_set = FAULT_VOLTAGE
        voltage_measured = -6
        fault_pattern = FAULT_PATTERN

        try:
            voltage_set = CS.voltage.set
            fault_pattern = CS.pat_wave
            voltage_measured = CS.voltage.measured

        except Exception as e:
            logger.warning(f"Tried to get voltage and pattern from CS to store but got {type(e)} instead ('{e}'). Storing the global values instead.")

        sig_params = {
            "position": CURRENT_POSITION.copy(),
            "time": getTime(date=True),
            "voltage_set": voltage_set,
            "voltage_measured": voltage_measured,
            "pattern": fault_pattern,
        }

        return sig_params


    def _handle_parseable_message(self, line_str):
        """Handle parseable messages and keywords."""
        sig_params = None
        if self.buffer is not None:  # Previous line was a keyword

            if line_str and line_str.strip() in KEYWORD_HANDLERS:
                logger.debug(f"Received keyword twice in succession ({line_str.strip()}, buffered: {self.buffer.strip()}). Ignoring.")

            else:
                if self.buffer == "Signature:" or self.buffer == "Alarm:":
                    sig_params = self._gather_signature_params()

                self.event_queue.put((self.device, self.buffer, line_str, sig_params))

            self.buffer = None
            
        elif line_str.strip() in KEYWORD_HANDLERS:
            self.buffer = line_str.strip()

        elif self._is_timings(line_str):
            logger.info(f"Received no keyword but asserted that the payload must be timings: {line_str[:min(10,len(line_str))]}...")
            self.event_queue.put((self.device, "Timings:", line_str, sig_params))

        elif self._is_alarm(line_str):
            logger.info(f"Received no keyword but asserted that the payload must be an alarm: {line_str[:min(10,len(line_str))]}...")
            self.event_queue.put((self.device, "Alarm:", line_str, sig_params))

        elif line_str == "for 30sec":
            logger.info(f"Received no keyword but asserted that target initiated a pause: {line_str[:min(10,len(line_str))]}...")
            self.event_queue.put((self.device, "Pause:", line_str, sig_params))
        
        elif self._is_parseable_string(line_str, len(VALID_SIGNATURE), "0123456789abcdef"):
            logger.info(f"Received no keyword but asserted that the payload must be a signature: {line_str[:min(10,len(line_str))]}...")
            sig_params = self._gather_signature_params()
            self.event_queue.put((self.device, "Signature:", line_str, sig_params))

        else:
            logger.debug(f"Received parseable line with no prior keyword: {line_str}")
            self.event_queue.put((self.device, None, line_str, sig_params))

    def _handle_unparseable_message(self, line_str, line):
        """Handle unparseable messages and update counters."""
        global BASENAME_FILES, TOTAL_PROGRESS, CURRENT_PROGRESS
        
        self.number_of_unparseables += 1
        self.number_of_unparseables_at_position_and_voltage += 1
        self.number_of_unparseables_at_position_and_voltage_in_a_row += 1

        if (self.target_state != OperationalState.NORMAL and 
            self.target_state != OperationalState.FIRST_UNPARSEABLE):
            logger.debug(f"Received unparseable signature while in state {self.target_state}. Will not store it.")
        else:
            logger.debug(f"Received unparseable signature: {line_str} | {line}")
            self._save_unparseable_signature(line)

        
        if self.number_of_unparseables_at_position_and_voltage_in_a_row >= 6:

            # Baudrate
            if self.number_of_recovery_attempts_at_position_and_voltage == 0: 
                if self.alternative_baudrate is not None and not args.dryrun and self.baudrate == TARGET_BAUDRATE:
                    self.ser.close()
                    logger.info(f"Switching to alternative baudrate {self.alternative_baudrate} for UART")
                    self._create_serial_connection(baudrate=self.alternative_baudrate)
                    self.target_state = OperationalState.TRYING_BAUDRATES

            # Stop faulting
            elif self.number_of_recovery_attempts_at_position_and_voltage == 1:
                self.ser.close()
                self.baudrate = TARGET_BAUDRATE
                self._create_serial_connection()

                logger.info(f"Received {self.number_of_unparseables_at_position_and_voltage_in_a_row} unparseable messages. Disabling ChipShouter.")
                self.target_state = OperationalState.CS_DISABLED
                self.cs.request_disable("unparseable_signature_check")

            # Target reset
            elif self.number_of_recovery_attempts_at_position_and_voltage == 2:
                logger.info("Unparseable messages persist. Resetting target.")
                self._append_last_param("reset_required")
                self.reset()

            if self.number_of_recovery_attempts_at_position_and_voltage >= 2:
                self._append_last_param("unresolved")
                self.number_of_recovery_attempts_at_position_and_voltage = 0
            else:
                self.number_of_recovery_attempts_at_position_and_voltage += 1

        self._check_voltage_reduction()

    def _save_unparseable_signature(self, line):
        """Save unparseable signature to file."""
        try:
            with open(BASENAME_FILES + "_unparseable.raw", "ab") as f:
                num_bytes = (int(TOTAL_PROGRESS).bit_length() + 7) // 8
                progress_bytes = int(CURRENT_PROGRESS).to_bytes(num_bytes, byteorder='big')
                f.write((b'\xff' + b'\x00')*2 + progress_bytes + (b'\xff' + b'\x00')*2 + line)
        except (OverflowError, ValueError) as e:
            # Fallback: use a larger fixed size 
            logger.warning(f"Failed to save unparseable signature with progress {CURRENT_PROGRESS}: {e}. Using 8-byte fallback.")
            try:
                progress_bytes = int(CURRENT_PROGRESS).to_bytes(8, byteorder='big')
                f.write((b'\xff' + b'\x00')*2 + progress_bytes + (b'\xff' + b'\x00')*2 + line)
            except (OverflowError, ValueError) as e2:
                # Last resort: save without progress bytes
                logger.error(f"Cannot save progress bytes even with 8 bytes: {e2}. Saving signature without progress.")
                progress_bytes = b'\x00'*8
                f.write((b'\xff' + b'\x00')*2 + progress_bytes + (b'\xff' + b'\x00')*2 + line)

    def _check_voltage_reduction(self):
        """Check if voltage should be reduced due to unparseable messages."""
        global FAULT_VOLTAGE, FAULT_VOLTAGE_START_AT_STEP, TRIES_LEFT_PER_POSITION
        global FAULT_VOLTAGE_INCREMENTS, MIN_VOLTAGE, VARIABLE_STATE, AXES
        
        if self.number_of_unparseables_at_position_and_voltage >= max(TRIES_PER_POSITION // 3, 10):
            logger.info(f"Received {self.number_of_unparseables_at_position_and_voltage} unparseable messages. Lowering voltage.")
            self.number_of_unparseables_at_position_and_voltage = 0
            self.number_of_unparseables_at_position_and_voltage_in_a_row = 0
            TRIES_LEFT_PER_POSITION = TRIES_PER_POSITION

            
            if FAULT_VOLTAGE - FAULT_VOLTAGE_INCREMENTS > MIN_VOLTAGE:
                FAULT_VOLTAGE -= FAULT_VOLTAGE_INCREMENTS
                FAULT_VOLTAGE_START_AT_STEP -= FAULT_VOLTAGE_INCREMENTS
                self.cs.change(voltage=FAULT_VOLTAGE)
            else:
                logger.warning(f"Voltage already too low ({FAULT_VOLTAGE} V). Jogging to next position.")
                VARIABLE_STATE = 0
                if jog(AXES):
                    self.stop_event.set()

    def _update_state_machine(self, parseable):
        """Update the operational state machine based on message parseability."""
        
        if self.target_state == OperationalState.NORMAL:
            if not parseable:
                self.target_state = OperationalState.FIRST_UNPARSEABLE
                logger.info("Received the first of potentially many unparseable signatures")
                self._log_unparseable("first_unparseable")
                
        elif (self.target_state == OperationalState.FIRST_UNPARSEABLE and 
            self.number_of_unparseables_at_position_and_voltage >= 3 and AUTO_RESET_TARGET):
            if parseable:
                self._append_last_param("single_unparseable")

        elif (self.target_state == OperationalState.TRYING_BAUDRATES and 
            self.number_of_unparseables_at_position_and_voltage >= 6 and AUTO_RESET_TARGET):
            if parseable:
                logger.debug("Successfully received a parseable message after switching baudrate.")
                self._append_last_param("changed_baudrate")
                
        elif (self.target_state == OperationalState.CS_DISABLED and 
            self.number_of_unparseables_at_position_and_voltage >= 9 and AUTO_RESET_TARGET):
            if parseable:
                self._append_last_param("unparseable_while_faulting") #temporarily_unparseable

        

    def _reset_state_machine(self, parseable, line_str):
        """Reset state machine when parseable message received."""
        if parseable and self.target_state != OperationalState.NORMAL:
            logger.info("Resuming normal operations as parseable message was received")
            logger.debug(f"Message that changed state: {line_str}")

            self.number_of_unparseables_at_position_and_voltage_in_a_row = 0
            
            old_state = self.target_state
            self.target_state = OperationalState.NORMAL
            self.uart_scan_already_tried = False
            
            if old_state != OperationalState.FIRST_UNPARSEABLE and AUTO_RESET_TARGET:
                if "unparseable_signature_check" in self.cs.disable_requests:
                    self.cs.release_disable("unparseable_signature_check")

    def _handle_empty_lines(self):
        """Handle case when no data is received."""
        self.number_of_empty += 1
        if self.number_of_empty > 50:
            logger.warning(f"Received {self.number_of_empty} empty lines. Resetting target.")
            self.reset()

    def _handle_serial_error(self, e):
        """Handle serial communication errors."""
        tb = traceback.extract_tb(e.__traceback__)
        if tb:
            filename, lineno, func, text = tb[-1]
            logger.error(f"Serial error ({type(e)}) on {self.device}: {filename}:{lineno} {text}, '{e}'")
        else:
            logger.error(f"Serial error ({type(e)}) on {self.device}: {e}")

        self.number_of_sr_errors += 1
        if self.number_of_sr_errors > 10:
            self._handle_critical_error()

    def _handle_critical_error(self):
        """Handle critical serial errors."""
        try:
            logger.error("More than 10 serial errors. Resetting target...")
            self.reset()
        except Exception as e:
            logger.error(f"Critical error handling failed: {e}. Exiting application.")
            export_params()
            save_checkpoint()
            self.stop_event.set()
        finally:
            self.number_of_sr_errors = 0

    def listen(self):
        """Main listening loop for serial communication."""
        self._create_serial_connection()
        
        try:
            while not self.stop_event.is_set():
                # logger.debug("Heartbeat from target listener")
                try:
                    line = self.ser.read_until(b'\r\n', self.max_read_length)
                    
                    if line:
                        self.number_of_empty = 0
                        
                        # Truncate overly long messages
                        if len(line) > self.max_read_length:
                            line = line[:self.max_read_length] + b'\r\n'
                        
                        parseable, line_str = self._serial_to_string(line)
                        
                        with target_lock:

                            # Handle reset states
                            if self._handle_reset_state(line_str):
                                continue
                            
                            if self.banner_provided:
                                # Detect new resets
                                if self._detect_target_reset(line_str):
                                    continue

                            # If not banner is provided, check state for start of reset
                            elif self.target_state == OperationalState.STARTED_FIRST_RESET:

                                if not self.time_last_reset:
                                    self.time_last_reset = time.time()

                                self.target_state = OperationalState.IN_FIRST_RESET
                                continue

                            # Process messages
                            if parseable:
                                self._handle_parseable_message(line_str)
                            else:
                                self._handle_unparseable_message(line_str, line)
                            
                            # Update state machine
                            self._update_state_machine(parseable)
                            
                            # Check for state machine reset
                            self._reset_state_machine(parseable, line_str)
                    else:
                        self._handle_empty_lines()
                        
                except Exception as e:
                    self._handle_serial_error(e)
                    continue
                else:
                    if random.random() < 0.2:
                        self.number_of_sr_errors = 0
                        
        finally:
            self.ser.close()

class CS_Connector:
    def __init__(self, port=None, serial_number=None):
        self._lock = threading.RLock()
        self.port = port or CHIPSHOUTER_PORT
        self.serial_number = serial_number or CHIPSHOUTER_SERIAL_NUMBER
        self._chipshouter = None
        self.disable_requests = []
        self.enabled = False
        self.connect()

    def __getattr__(self, name):

        if name in ("_chipshouter", "_lock", "port", "serial_number", "disable_requests", "enabled"):
            return object.__getattribute__(self, name)

        with object.__getattribute__(self, "_lock"):
            try:                
                attr = getattr(self._chipshouter, name)

                if callable(attr): # if the attribute is a method
                    def wrapper(*args, **kwargs):
                        return attr(*args, **kwargs)
                    return wrapper
                
                return attr
            
            except Exception as e:
                self.handleException(e, msg=f"accessing '{name}'", retry_fun=self.__getattr__, retry_args=(name,), part_of_exception_handling=True)

    def __setattr__(self, name, value):

        if name in {"_chipshouter", "_lock", "port", "serial_number", "disable_requests", "enabled"}:
            super().__setattr__(name, value)
            return

        with object.__getattribute__(self, "_lock"):
            try:
                setattr(self._chipshouter, name, value)

            except Exception as e:
                self.handleException(e, msg=f"setting '{name}' to '{value}'", retry_fun=self.__setattr__, retry_args=(name, value), part_of_exception_handling=True)

    def handleException(self, e, msg=None, retry_fun=None, retry_args={}, part_of_exception_handling=False):

        if part_of_exception_handling:

            if retry_fun and callable(retry_fun) and (getattr(retry_fun, "__name__", str(retry_fun)) == "__getattr__" or getattr(retry_fun, "__name__", str(retry_fun)) == "__setattr__"):
                logger.error(f"Exception caught while {f' {msg}' if msg else 'using getter or setter'}: {e}. Resetting ChipShouter and retrying...")

            else:
                logger.error(f"Exception caught while handling another exception{f' {msg}' if msg else ''}: {e}. Resetting ChipShouter and retrying...")

            self.reset()

        else:
            if isinstance(e, Reset_Exception):
                logger.warning(f"Caught ChipSHOUTER 'Reset Exception'{f' {msg}' if msg else ''}. Reconnecting...")
                logger.debug(f"Exception details: {e}")
                time.sleep(5)
                self.reconnect(part_of_exception_handling=True)

            elif isinstance(e, Max_Retry_Exception):
                logger.error(f"Caught ChipSHOUTER 'Max Retry Exception'{f' {msg}' if msg else ''}. Starting selfheal...")
                logger.debug(f"Exception details: {e}")
                self.selfheal(part_of_exception_handling=True)

            else:
                logger.error(f"Caught {type(e)} while{f' {msg}' if msg else ' interacting with the ChipSHOUTER'}: '{e}'. Starting selfheal...")
                self.selfheal(part_of_exception_handling=True)

        if stop_event.is_set():

            if retry_fun:

                if callable(retry_fun):
                    retry_name = getattr(retry_fun, "__name__", str(retry_fun))
                else:
                    retry_name = f"non-callable (!) '{repr(retry_fun)}'"

                logger.warning(f"Would have called '{retry_name}({retry_args})' but CS exception handling aborted because stopping event is set!")

            else:
                logger.debug("CS exception handling stopped gracefully because stopping event is set.")

        elif callable(retry_fun):
            try:
                if retry_args is None:
                    retry_fun(part_of_exception_handling=True)
                else:
                    retry_fun(*retry_args, part_of_exception_handling=True)

            except Exception as e:
                logger.error(f"Retry failed: {e} ({type(e)}). Resetting ChipShouter...")
                self.reset()

        elif retry_fun is not None:
            logger.error(f"Expected callable but got: {retry_fun}. This should not happen! Stopping...")
            stop_event.set()

    def request_disable(self, reason=""):
        with self._lock:

            if reason in self.disable_requests:
                logger.warning(f"Disable request with reason '{reason}' already exists: {self.disable_requests}.")

            if self.enabled:
                self.arm(False, reason)

            else:
                logger.debug(f"Tried to disable ChipShouter with reason {reason} while it is already disabled. Pending disable requests: {self.disable_requests}")

            self.disable_requests.append(reason)

    def release_disable(self, reason=""):
        with self._lock:

            if len(self.disable_requests) == 0:
                logger.warning(f"Tried to enable ChipShouter with reason {reason} but there are no disable requests pending. This should not happen, will enable ChipShouter anyway.")
            
            elif reason in self.disable_requests:
                self.disable_requests.remove(reason)

            else:
                logger.warning(f"Disable request with reason '{reason}' does not exist: {self.disable_requests}. Removing the last element...")
                self.disable_requests.pop()

            if len(self.disable_requests) == 0:
                self.arm(True, reason)

            else:
                logger.debug(f"Tried to enable ChipShouter with reason {reason} but it still has disable requests pending: {self.disable_requests}. Not enabling it yet.")

    def getInfo(self, part_of_exception_handling=False):
         
        with self._lock:

            try:
                return str(self._chipshouter)

            except Exception as e:
                self.handleException(e, msg="printing CS info", retry_fun=self.getInfo, part_of_exception_handling=part_of_exception_handling)

    def is_connected(self, part_of_exception_handling=False):

        with self._lock:

            if self._chipshouter is None:
                return False

            try:
                if self._chipshouter.status(): # .state returns a string ('armed' etc.) .status() returns a boolean
                    return True 

            except Exception:
                return False

        return False
    
    def find_port(self, part_of_exception_handling=False):
        try:
            self.port = None
            self.port = find_tty_path(self.serial_number)

        except Exception as e:
            logger.error(f"Caught {type(e)} while trying to get the correct port. This should not happen! Error: {e}")
            stop_event.set()
            return

        else:
            if self.port is None:
                logger.error("Could not find a port corresponding to the ChipSHOUTER serial number. Please check the connection.")
                stop_event.set()

            else:
                logger.info(f"Found ChipSHOUTER port: {self.port}")

    def connect(self, part_of_exception_handling=False):

        if self.is_connected():
            logger.info("ChipSHOUTER is already connected.")
            return

        
        i = 0
        while True:

            with self._lock:
                
                if i > 3:
                    logger.error("Failed to connect to ChipSHOUTER after 3 attempts. Continuing without connection.")
                    return
                
                i += 1

                try:
                    if args.dryrun:
                        logger.warning("Dry-run mode enabled. Using dummy ChipSHOUTER!")
                        self._chipshouter = DummyChipSHOUTER(CHIPSHOUTER_PORT)
                    else:
                        self._chipshouter = ChipSHOUTER(self.port)

                except Exception as e:
                    logger.error(f"{type(e)} while connecting to ChipSHOUTER: {e}. Trying to get the correct port and retrying in {5 * i} s, {3 - i} tries left...")
                    self.find_port()
                    time.sleep(5 * i)
                    continue

                else:
                    if self.is_connected():
                        logger.info(f"Connected to ChipSHOUTER.")
                        return
                    else:
                        logger.warning(f"Failed to connect to ChipSHOUTER. Retrying in {5 * i} s, {3 - i} tries left...")
                        time.sleep(5 * i)

    # Connects, initializes, and arms the ChipShouter while connect() does just the connecting
    def reconnect(self, part_of_exception_handling=False):

        with self._lock:

            logger.info("Reconnecting ChipSHOUTER...")
            self.connect()

            if self.is_connected():
                logger.info("ChipSHOUTER reconnected successfully.")

                self.initialize(part_of_exception_handling=part_of_exception_handling)

                self.arm(self.enabled, "reconnect", part_of_exception_handling=part_of_exception_handling)

            else:
                logger.warning("Failed to reconnect to ChipSHOUTER. Resetting ChipShouter...")
                self.reset()

    def ready_for_commands_with_timeout(self, timeout=5, retry_fun=None, retry_args=None, part_of_exception_handling=False):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._chipshouter.ready_for_commands)
            try:
                future.result(timeout=timeout)

            except concurrent.futures.TimeoutError:
                logger.error("ready_for_commands() timed out after 5 seconds. Executing selfheal().")
                self.selfheal()

            except Exception as e:
                self.handleException(e, msg="ready_for_commands", retry_fun=retry_fun, retry_args=retry_args, part_of_exception_handling=part_of_exception_handling)

    def initialize(self, part_of_exception_handling=False):

        try:
            with self._lock:

                logger.debug("Initializing ChipSHOUTER.")

                self.ready_for_commands_with_timeout(10, retry_fun=self.initialize, part_of_exception_handling=part_of_exception_handling)
                
                self._chipshouter.armed = 0

                self._chipshouter.pat_wave = FAULT_PATTERN
                self._chipshouter.voltage = FAULT_VOLTAGE
                self._chipshouter.pulse.deadtime = DEAD_TIME
                self._chipshouter.pat_enable = 1
                self._chipshouter.pulse.repeat = 1

                self._chipshouter.hwtrig_term = 1
                self._chipshouter.hwtrig_mode = 1
                self._chipshouter.emode = 0

                self._chipshouter.mute = 1
                self._chipshouter.arm_timeout = 20 # minutes

                self.ready_for_commands_with_timeout(10, retry_fun=self.initialize, part_of_exception_handling=part_of_exception_handling)
                
                # Summarize the pattern: count leading zeros, ones, and trailing zero
                pattern = self._chipshouter.pat_wave
                num_zeros = next((i for i, v in enumerate(pattern) if v != 0), len(pattern))
                num_ones = next((i for i, v in enumerate(pattern[num_zeros:]) if v != 1), len(pattern) - num_zeros)
                trailing_zero = (len(pattern) > num_zeros + num_ones and pattern[num_zeros + num_ones] == 0)

                logger.info(f"Initialized ChipSHOUTER with board id {str(self._chipshouter.id).strip()} and api version {self._chipshouter.api_version}")
                logger.info(f"   - Voltage: {self._chipshouter.voltage.set} V")
                logger.info(f"   - Pattern: {num_zeros} zeros, {num_ones} ones" + (", trailing zero" if trailing_zero else ""))
                logger.info(f"   - Pulse repeat: {self._chipshouter.pulse.repeat}")

        except Exception as e:
            self.handleException(e, msg=f"initializing ChipSHOUTER", retry_fun=self.initialize, part_of_exception_handling=part_of_exception_handling)

    def arm(self, arm=True, reason="", part_of_exception_handling=False):

        req = 'armed' if arm else 'disarmed'
        req_txt = 'arm' if arm else 'disarm'

        if arm and len(self.disable_requests) > 0:
            logger.warning(f"Overwriting the disable queue: {self.disable_requests}. Consider using release_disable() instead!")
            self.disable_requests = []

        self.enabled = arm
        logger.info(f"Trying to {req_txt} ChipShouter ({reason})")

        i = 0
        with self._lock:
            while True:
                
                if i > 3:
                    logger.error(f"Failed to {req_txt} ChipSHOUTER after 3 attempts. Trying to recover.")
                    self.handleException(Exception(f"Tried to {req_txt} but gave up after three tries."), msg=f"{req_txt} ChipSHOUTER. state={self._chipshouter.state}", retry_fun=self.arm, retry_args=(arm,), part_of_exception_handling=part_of_exception_handling)
                    return
                
                i += 1

                try:
                    if self._chipshouter.state == req:
                        logger.info(f"ChipSHOUTER is {req}.")
                        return
                
                    if self._chipshouter.state == 'fault':
                        self.handleException(Exception(f"Tried to {req_txt} but state is 'fault'"), msg=f"{req_txt} ChipSHOUTER. state={self._chipshouter.state}", retry_fun=self.arm, retry_args=(arm,), part_of_exception_handling=part_of_exception_handling)
                        return

                    self._chipshouter.armed = arm

                except Exception as e:
                    logger.error(f"{type(e)} while {req_txt} the ChipSHOUTER: {e}. Retrying in {5 * i} s, {3 - i} tries left...")
                    time.sleep(5 * i)
                    continue

                else:
                    try:
                        self.ready_for_commands_with_timeout(10, retry_fun=self.arm, retry_args=(arm,reason), part_of_exception_handling=part_of_exception_handling)

                        if self._chipshouter.state == "arming":
                            time.sleep(10)

                        if self._chipshouter.state == req:
                            logger.info(f"ChipShouter is now {req}")
                            return
                        
                        else:
                            logger.warning(f"Failed to check whether the ChipSHOUTER is {req}. Trying to recover...")
                            self.handleException(Exception(f"Failed to {req_txt} the ChipSHOUTER after three attempts"), msg=f"{req_txt} ChipSHOUTER. state={self._chipshouter.state}", retry_fun=self.arm, retry_args=(arm,), part_of_exception_handling=part_of_exception_handling)


                    except Exception as e2:
                        logger.error(f"{type(e2)} while checking if ChipSHOUTER is {req}: {e2}. Retrying in {5 * i} s, {3 - i} tries left...")
                        time.sleep(5 * i)
                        continue

    def reset(self, part_of_exception_handling=False):
        try:
            with self._lock:
                
                # Resetting ChipSHOUTER
                logger.info("Resetting ChipSHOUTER and reconnecting...")

                i = 1
                while True:
                    try:
                        self._chipshouter.reset = 1

                    except (OSError, IOError) as e:
                        logger.error(f"{type(e)} while setting reset bit on ChipSHOUTER: {e}. Retrying in {5 * i} s until this works...")
                        time.sleep(5 * i)

                        try:
                            self.connect()

                        except Exception as e:
                            pass

                        continue

                    else:
                        time.sleep(5)
                        
                        try:
                            self.connect()

                        except Exception as e:
                            logger.error(f"{type(e)} while connecting to ChipSHOUTER after reset: {e}. Retrying in {5 * i} s until this works...")
                            time.sleep(5 * i)
                            continue

                        else:
                            if self.is_connected():
                                logger.info(f"ChipShouter was reset and could be connected afterwards. Performing full reconnect...")
                                self.reconnect()
                                return
                            else:
                                logger.error(f"Although connect() raised no Exception, is_connected() retured False! Retrying in {5 * i} s until this works...")
                                time.sleep(5 * i)
                                continue

        except Exception as e:
            tb  = traceback.extract_tb(e.__traceback__)
            if tb:
                filename, lineno, func, text = tb[-1]
                logger.error(f"{type(e)} while resetting ChipSHOUTER: {filename} raised an error on line {lineno} (func {func}): {text}, '{e}'")
            else:
                logger.error(f"{type(e)} while resetting ChipSHOUTER: {e}.")

    def clear_faults(self, part_of_exception_handling=False):
        faults = []
        try:
            faults = self._chipshouter.faults_current

        except Exception:
            logger.warning(f"Selftest found: ChipSHOUTER is in fault state. Furthermore, we could not fetch latched faults. Resetting ChipShouter...")
            self.reset()
            return

        else:
            # Could query faults -> Trying to clear them
            logger.info(f"Selftest found: ChipSHOUTER is in fault state. Currently {('the following faults are latched: ' + faults + '. Trying to clear faults...') if faults else 'no faults are latched. Trying to clear faults anyway...'}")

            try:
                self._chipshouter.faults_current = 0

            except Exception as e:
                logger.warning(f"{type(e)} while clearing latched faults: {e}. Resetting ChipShouter...")
                self.reset()
                return

            else:
                try:
                    if self._chipshouter.state == 'fault':
                        logger.warning("Fault state could not be cleared. Resetting ChipShouter...")
                        self.reset()
                        return

                    else:
                        logger.info("Fault state was cleared.")
                        return # -> No reset
                except Exception as e2:
                    logger.warning(f"{type(e2)} while checking if fault state was cleared: {e2}. Resetting ChipShouter...")
                    self.reset()
                    return

    def selfheal(self, part_of_exception_handling=False):
        failed_on=""
        i = 0
        while True:
            if i > 20:
                logger.error(f"Selfheal ran for {i} times in a row without success. This seems unrecoverable. Exiting...")
                stop_event.set()

            i += 1

            try:
                with self._lock:

                    if not self.is_connected():
                        logger.warning("Selftest found: ChipSHOUTER is not connected.")
                        if failed_on == "connection":
                            logger.error(f"ChipSHOUTER Selftest failed twice on the same check: {failed_on}. Resetting ChipShouter")
                            self.reset()
                            continue
                        else:
                            logger.info("Selfheal triggered: Reconnecting...")
                            failed_on = "connection"
                            self.reconnect(part_of_exception_handling=part_of_exception_handling)
                            continue


                    logger.debug("selfheal reports ChipSHOUTER as connected")

                    if self._chipshouter.state == 'fault':
                        logger.warning("Selftest found: ChipSHOUTER reports state 'fault'.")
                        if failed_on == "fault":
                            logger.error(f"ChipSHOUTER Selftest failed twice on the same check: {failed_on}. Resetting ChipShouter")
                            self.reset()
                            continue
                        else:
                            logger.info("Selfheal triggered: Clearing faults...")
                            failed_on = "fault"
                            self.clear_faults()

                    logger.debug("selfheal reports ChipSHOUTER as not in fault state")

                    if (self.enabled and self._chipshouter.state == 'disarmed') or (not self.enabled and self._chipshouter.state == 'armed'):
                        logger.warning(f"Selftest found: ChipSHOUTER is falsefully {'armed' if self.enabled else 'disarmed'}.")
                        if failed_on == "arm":
                            logger.error(f"ChipSHOUTER Selftest failed twice on the same check: {failed_on}. Resetting ChipShouter")
                            self.reset()
                            continue
                        else:
                            logger.info(f"Selfheal triggered: {'arming' if self.enabled else 'disarming'}...")
                            failed_on = "arm"
                            self.arm(self.enabled, "selfheal", part_of_exception_handling=part_of_exception_handling)

            except Exception as e:
                tb  = traceback.extract_tb(e.__traceback__)
                if tb:
                    filename, lineno, func, text = tb[-1]
                    logger.error(f"Caught {type(e)} during CS selfheal: {filename} raised an error on line {lineno} (func {func}): {text}, '{e}'. Retrying in {5 * i} s, {20 - i} tries left...")
                else:
                    logger.error(f"Caught {type(e)} during CS selfheal: {e}. Retrying in {5 * i} s, {20 - i} tries left...")

                time.sleep(5 * i)
                self.reset()
                continue
            
            else:
                if failed_on == "":
                    logger.debug("ChipSHOUTER selftest returned positive. No selfheal was required.")
                    return True
                else:
                    logger.debug("ChipSHOUTER successfully performed selfheal.")
                    return False

                


    def change(self, timeHigh_ns=None, voltage=None, deadtime=None, silent=False, part_of_exception_handling=False):
        global FAULT_PATTERN, FAULT_VOLTAGE, DEAD_TIME, TARGET

        try:
            with self._lock:

                if timeHigh_ns is not None:
                    if not isinstance(timeHigh_ns, int) or timeHigh_ns < 0:
                        logger.error("timeHigh_ns must be a positive integer")
                    else:
                        if timeHigh_ns > MAX_HIGH_TIME_ns:
                            logger.error(f"timeHigh_ns can't be larger than {MAX_HIGH_TIME_ns} ns")
                        else:
                            no_of_ones = timeHigh_ns // MIN_HIGH_TIME_ns
                            if no_of_ones <= 0:
                                self.request_disable("user")
                            else:
                                no_of_zeros = 66 - no_of_ones

                                FAULT_PATTERN = [0] * no_of_zeros + [1] * no_of_ones + [0]
                                self._chipshouter.pat_wave = FAULT_PATTERN

                                if ''.join(str(x) for x in FAULT_PATTERN) == str(self._chipshouter.pat_wave).strip():
                                    if not silent: logger.info(f"Changed fault pattern to have a delay of {no_of_zeros*MIN_HIGH_TIME_ns} ns and high-side of {no_of_ones*MIN_HIGH_TIME_ns} ns")
                                else:
                                    logger.error(f"Tried to set fault pattern to {FAULT_PATTERN} but CS reports {self._chipshouter.pat_wave}")

                if voltage is not None:
                    if not isinstance(voltage, (int, float)) or voltage < 0:
                        logger.error("Voltage must be a positive number")
                    else:
                        if voltage < MIN_VOLTAGE or voltage > MAX_VOLTAGE:
                            logger.error(f"Voltage must be between {MIN_VOLTAGE} and {MAX_VOLTAGE}V")
                        elif (voltage // 30) + 1 > DEAD_TIME:
                            logger.warning(f"Voltage not set because it might be to high. ChipSHOUTER charges 30V/ms in the worst case. Based on the current dead-time ({DEAD_TIME} ms), the voltage should be lower than {DEAD_TIME * 30} V to ensure it can properly pulse")
                        else:
                            TARGET.number_of_unparseables_at_position_and_voltage = 0
                            TARGET.number_of_recovery_attempts_at_position_and_voltage = 0
                            FAULT_VOLTAGE = voltage
                            self._chipshouter.voltage = voltage
                            
                            if float(self._chipshouter.voltage.set) == FAULT_VOLTAGE:
                                if not silent: logger.info(f"Changed fault voltage to {FAULT_VOLTAGE} V")
                            else:
                                logger.error(f"Tried to set fault voltage to {FAULT_VOLTAGE}V but CS reports {self._chipshouter.voltage.set} V")

                if deadtime is not None:
                    if not isinstance(deadtime, int) or deadtime < 0:
                        logger.error("Deadtime must be a positive number")
                    else:
                        if deadtime < 1 or deadtime > 1000:
                            logger.error(f"Deadtime must be between 1 and 1000 ms")
                        elif deadtime < (FAULT_VOLTAGE // 30) + 1:
                            logger.warning(f"Deadtime not set because it might be to low. ChipSHOUTER charges 30V/ms in the worst case. Based on the current voltage ({FAULT_VOLTAGE}V), the deadtime should be at least {(FAULT_VOLTAGE // 30) + 1} ms to ensure it can properly pulse")
                        else:
                            DEAD_TIME = deadtime
                            self._chipshouter.pulse.deadtime = deadtime

                            if int(self._chipshouter.pulse.deadtime) == deadtime:
                                if not silent: logger.info(f"Changed dead-time to {deadtime} ms")
                            else:
                                logger.error(f"Tried to set deadtime to {deadtime} ms but CS reports {int(self._chipshouter.pulse.deadtime)} ms")

                self.ready_for_commands_with_timeout(10, retry_fun=self.change, retry_args=(timeHigh_ns, voltage, deadtime, silent), part_of_exception_handling=part_of_exception_handling)

        except Exception as e:
            self.handleException(e, f"changing ChipShouter parameters", retry_fun=self.change, retry_args=(timeHigh_ns, voltage, deadtime, silent), part_of_exception_handling=part_of_exception_handling)

""" 
### Checkpoint logic
"""

def list_checkpoints():
    files = sorted(glob.glob("*_checkpointv4.pkl"))
    checkpoints = []
    for f in files:
        try:
            with open(f, "rb") as fp:
                data = pickle.load(fp)
                checkpoints.append((f, data.get("checkpoint_time", "unknown")))
        except Exception:
            checkpoints.append((f, "corrupt"))
    return checkpoints

def save_checkpoint():
    checkpoint = {
        "BOUNDARIES": BOUNDARIES,
        "CURRENT_POSITION": CURRENT_POSITION,
        "REFERENCE_POINT": REFERENCE_POINT,
        "TRIES_LEFT_PER_POSITION": TRIES_LEFT_PER_POSITION,
        "CONFIRMED_FAULTS": CONFIRMED_FAULTS,
        "CONFIRMED_ALARMS": CONFIRMED_ALARMS,
        "PAST_TIMINGS": PAST_TIMINGS,
        "CURRENT_PROGRESS": CURRENT_PROGRESS,
        "TOTAL_PROGRESS": TOTAL_PROGRESS,
        "TARGET_NAME": TARGET_NAME,
        "checkpoint_time": getTime(date=True)
    }
    with open(CHECKPOINT_FILE, "wb") as f:
        pickle.dump(checkpoint, f)
    logger.info(f"Saved checkpoint at {checkpoint['checkpoint_time']}")

class LoadBoundariesDisplay(ModalScreen):

    def __init__(self, axes):
        super().__init__()
        self.axes = axes
        self.msg = "Was the target moved, i.e., do the boundaries need adjustment?"

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(self.msg, id="question"),
            Button("No, target did not move", variant="primary", id="no"),
            Button("Yes, set new reference point", variant="primary", id="yes"),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "no":
            logger.info("User claims that target was not moved. Continuing with boundaries from last session without adjusting them.")
            self.dismiss(False)
            
        elif event.button.id == "yes":
            logger.info("User claims that target was moved. Requesting new reference point.")
            self.dismiss(True)

""" 
### Functions that export results during target-initiated pauses or at the end
"""
def export_params():
    # export params and whether they resulted in parseable, unparseable, or faulted signatures
    global SIGNATURES_PARAMS
    
    try:
        if len(SIGNATURES_PARAMS) == 0:
            logger.info("No parameters tried. Skipping export of parameters.")
            return
        
        csv_params_filename = TARGET_NAME + "_parameter_collection_v5.csv"
        file_exists = os.path.exists(csv_params_filename)
        write_header = not file_exists or os.path.getsize(csv_params_filename) == 0

        with open(csv_params_filename, "a", newline="") as csvfile:

            fieldnames = ["time", "result", "x", "y", "z", "voltage_set", "voltage_measured", "between_trigger_and_signGen_ms", "trigger_duration_ns", "tip_diameter_mm", "tip_winding", "pattern"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            for params in SIGNATURES_PARAMS:
                pos = params.get("position", {})
                writer.writerow({
                    "time": params.get("time", getTime(date=True)),
                    "result": params.get("result"),
                    "x": pos.get("X"),
                    "y": pos.get("Y"),
                    "z": pos.get("Z"),
                    "voltage_set": params.get("voltage_set"),
                    "voltage_measured": params.get("voltage_measured"),
                    "between_trigger_and_signGen_ms": params.get("between_trigger_and_signGen_ms", ""),
                    "trigger_duration_ns": params.get("trigger_duration_ns", ""),
                    "tip_diameter_mm": TIP_USED.get("diameter_mm"),
                    "tip_winding": TIP_USED.get("winding"),
                    "pattern": params.get("pattern") #''.join(str(x) for x in params.get("pattern", [])),
                })
            logger.info(f"Exported tried parameters to {csv_params_filename}")

    except Exception as e:
        logger.error(f"Failed to export parameters: {e}")
    
    else:
        SIGNATURES_PARAMS = []

def export_faults_and_map(resolution=50):

    csv_results_filename = None
    csv_alarm_filename = None
    results_mapname = None
    alarm_mapname = None

    if len(CONFIRMED_FAULTS) == 0:
        logger.info("No faults found. Skipping export of results and fault map.")
    else:
        try:

            # 1. Write CSV
            csv_results_filename = BASENAME_FILES + "_results.csv"

            if os.path.exists(csv_results_filename):

                i = 2
                while os.path.exists(csv_results_filename[:-4] + "_" + str(i) + ".csv"):
                    i += 1

                csv_results_filename = csv_results_filename + "_" + str(i) + ".csv"

            with open(csv_results_filename, "w", newline="") as csvfile:
                fieldnames = ["x", "y", "z", "time", "voltage_set", "voltage_measured", "pattern", "signature"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for fault in CONFIRMED_FAULTS:
                    pos = fault.get("position", {})
                    writer.writerow({
                        "x": pos.get("X"),
                        "y": pos.get("Y"),
                        "z": pos.get("Z"),
                        "time": fault.get("time"),
                        "voltage_set": fault.get("voltage_set"),
                        "voltage_measured": fault.get("voltage_measured"),
                        "pattern": fault.get("pattern"),
                        "signature": fault.get("signature"),
                    })

            logger.info(f"Exported {len(CONFIRMED_FAULTS)} faults to {csv_results_filename}")

            # 2. Create XY fault map
            results_mapname = BASENAME_FILES + "_faultmap" + ".png"
            if os.path.exists(results_mapname):

                i = 2
                while os.path.exists(results_mapname[:-4] + "_" + str(i) + ".png"):
                    i += 1

                results_mapname = results_mapname[:-4] + "_" + str(i) + ".png"

            # Extract x and y coordinates from CONFIRMED_FAULTS
            x_faults = [fault["position"]["X"] for fault in CONFIRMED_FAULTS]
            y_faults = [fault["position"]["Y"] for fault in CONFIRMED_FAULTS]
            
            # Create a grid for the heatmap
            x_bins = np.linspace(BOUNDARIES["X"]["RIGHT"], BOUNDARIES["X"]["LEFT"], resolution)
            y_bins = np.linspace(BOUNDARIES["Y"]["DOWN"], BOUNDARIES["Y"]["UP"], resolution)
            
            # Create 2D histogram
            hist, _, _ = np.histogram2d(x_faults, y_faults, bins=[x_bins, y_bins])
            
            # Create the plot
            plt.figure(figsize=(10, 8))
            
            # Plot heatmap
            plt.imshow(hist.T,  # Transpose to match coordinate system
                    extent=[BOUNDARIES["X"]["RIGHT"], BOUNDARIES["X"]["LEFT"],
                            BOUNDARIES["Y"]["DOWN"], BOUNDARIES["Y"]["UP"]],
                    origin='lower',  # Place (0,0) at bottom left
                    aspect='auto',
                    cmap='hot',
                    interpolation='gaussian')
            
            # Invert x-axis because that is how our motors are set up
            plt.gca().invert_xaxis()
            
            # Add colorbar
            plt.colorbar(label='Number of Faults')
            
            # Add labels and title
            plt.xlabel('X Position (mm)')
            plt.ylabel('Y Position (mm)')
            plt.title('Fault Distribution Heatmap')
            
            # Show grid
            plt.grid(True, alpha=0.3)
            plt.scatter(x_faults, y_faults, color='blue', alpha=0.5, s=20)

            plt.savefig(results_mapname)

            logger.info(f"Saved fault map to {results_mapname}")
        except Exception as e:
            logger.error(f"Failed to export results at the end: {e}")
            return

    if len(CONFIRMED_ALARMS) == 0:
        logger.info("No alarms found. Skipping export of alarms and alarm map.")
    else:
        try:
            csv_alarm_filename = BASENAME_FILES + "_alarms.csv"

            if os.path.exists(csv_alarm_filename):

                i = 2
                while os.path.exists(csv_alarm_filename[:-4] + "_" + str(i) + ".csv"):
                    i += 1

                csv_alarm_filename = csv_alarm_filename + "_" + str(i) + ".csv"

            with open(csv_alarm_filename, "w", newline="") as csvfile:
                alarm_fields = [alarm for alarm in ALARMS_DEFINED if "TEST_ALARM" not in alarm]
                fieldnames = ["x", "y", "z", "time", "voltage_set", "voltage_measured", "pattern"] + alarm_fields
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for alarm in CONFIRMED_ALARMS:
                    pos = alarm.get("position", {})
                    row = {
                        "x": pos.get("X"),
                        "y": pos.get("Y"),
                        "z": pos.get("Z"),
                        "time": alarm.get("time"),
                        "voltage_set": alarm.get("voltage_set"),
                        "voltage_measured": alarm.get("voltage_measured"),
                        "pattern": alarm.get("pattern"),
                    }
                    alarms_list = alarm.get("alarms", [])
                    for alarm_name in alarm_fields:
                        row[alarm_name] = "x" if alarm_name in alarms_list else ""
                    writer.writerow(row)

            logger.info(f"Exported {len(CONFIRMED_ALARMS)} alarms to {csv_alarm_filename}")

            alarm_mapname = BASENAME_FILES + "_alarmmap" + ".png"
            if os.path.exists(alarm_mapname):

                i = 2
                while os.path.exists(alarm_mapname[:-4] + "_" + str(i) + ".png"):
                    i += 1

                alarm_mapname = alarm_mapname[:-4] + "_" + str(i) + ".png"

            x_alarms = [alarm["position"]["X"] for alarm in CONFIRMED_FAULTS]
            y_alarms = [alarm["position"]["Y"] for alarm in CONFIRMED_FAULTS]
            
            x_bins = np.linspace(BOUNDARIES["X"]["RIGHT"], BOUNDARIES["X"]["LEFT"], resolution)
            y_bins = np.linspace(BOUNDARIES["Y"]["DOWN"], BOUNDARIES["Y"]["UP"], resolution)
            
            hist, _, _ = np.histogram2d(x_alarms, y_alarms, bins=[x_bins, y_bins])
            
            plt.figure(figsize=(10, 8))
            plt.imshow(hist.T,  # Transpose to match coordinate system
                    extent=[BOUNDARIES["X"]["RIGHT"], BOUNDARIES["X"]["LEFT"],
                            BOUNDARIES["Y"]["DOWN"], BOUNDARIES["Y"]["UP"]],
                    origin='lower',  # Place (0,0) at bottom left
                    aspect='auto',
                    cmap='hot',
                    interpolation='gaussian')
            
            plt.gca().invert_xaxis()
            plt.colorbar(label='Number of Alerts')
            
            plt.xlabel('X Position (mm)')
            plt.ylabel('Y Position (mm)')
            plt.title('Alarm Distribution Heatmap')
            
            plt.grid(True, alpha=0.3)
            plt.scatter(x_alarms, y_alarms, color='blue', alpha=0.5, s=20)

            plt.savefig(alarm_mapname)

            logger.info(f"Saved alarm map to {alarm_mapname}")
        except Exception as e:
            logger.error(f"Failed to export alarms at the end: {e}")
            return

    # Move files to a separate directory
    new_dir = ""
    try:
        # Create folder structure TARGET_BASENAME/DATE_TIME
        if TARGET_NAME:
            if not os.path.exists(TARGET_NAME): 
                os.makedirs(TARGET_NAME)
            new_dir = os.path.join(TARGET_NAME, BASENAME_FILES.split("_")[0])
        else:
            if not os.path.exists("OtherTargets"):
                os.makedirs("OtherTargets")
            new_dir = os.path.join("OtherTargets", BASENAME_FILES.split("_")[0])

        if not new_dir:
            raise Exception(f"Could not build target directory from Basename {BASENAME_FILES} and Target {TARGET_NAME}. As a result, it cannot move files.")
        
        if not os.path.exists(new_dir):
            os.makedirs(new_dir)

        # Move checkpoint (and append ".finished" to the filename)
        if CHECKPOINT_FILE and os.path.exists(CHECKPOINT_FILE):
            os.rename(CHECKPOINT_FILE, os.path.join(new_dir, CHECKPOINT_FILE + ".finished"))
            logger.info(f"Moved checkpoint file to {os.path.join(new_dir, CHECKPOINT_FILE + ".finished")}")
        else:
            logger.info(f"No checkpoint file to move. Looked for {CHECKPOINT_FILE if CHECKPOINT_FILE else ''}")

        # Move unparseable signatures file
        if os.path.exists(BASENAME_FILES + "_unparseable.raw"):
            os.rename(BASENAME_FILES + "_unparseable.raw", os.path.join(new_dir, BASENAME_FILES + "_unparseable.raw"))
            logger.info(f"Moved unparseable signatures file to {os.path.join(new_dir, BASENAME_FILES + "_unparseable.raw")}")
        elif TARGET.number_of_unparseables > 0:
            logger.error(f"Found no unparseable signatures file to move even though {TARGET.number_of_unparseables} of such signatures were incountered in this run. Looked for {BASENAME_FILES + '_unparseable.raw'}")
        else:
            logger.info(f"No unparseable signatures were found during this run")
            

        # Move results CSV
        if csv_results_filename and os.path.exists(csv_results_filename):
            os.rename(csv_results_filename, os.path.join(new_dir, csv_results_filename))
            logger.info(f"Moved results CSV to {os.path.join(new_dir, csv_results_filename)}")
        elif len(CONFIRMED_FAULTS) > 0:
            logger.error(f"{('Looked for ' + csv_results_filename + ' but found') if csv_results_filename else 'Found'} no results CSV to move although there should have been faulty signatures exported!") 
            

        # Move faultmap
        if results_mapname and os.path.exists(results_mapname):
            os.rename(results_mapname, os.path.join(new_dir, results_mapname))
            logger.info(f"Moved faultmap to {os.path.join(new_dir, results_mapname)}")
        elif len(CONFIRMED_FAULTS) > 0:
            logger.error(f"{('Looked for ' + results_mapname + ' but found') if results_mapname else 'Found'} no results map to move although there should have been faulty signatures exported!") 

        # Move alarm CSV
        if csv_alarm_filename and os.path.exists(csv_alarm_filename):
            os.rename(csv_alarm_filename, os.path.join(new_dir, csv_alarm_filename))
            logger.info(f"Moved alarm CSV to {os.path.join(new_dir, csv_alarm_filename)}")
        elif len(CONFIRMED_ALARMS) > 0:
            logger.error(f"{('Looked for ' + csv_alarm_filename + ' but found') if csv_alarm_filename else 'Found'} no alarm CSV to move although there should have been faulty signatures exported!") 
            

        # Move alarmmap
        if alarm_mapname and os.path.exists(alarm_mapname):
            os.rename(alarm_mapname, os.path.join(new_dir, alarm_mapname))
            logger.info(f"Moved alarmmap to {os.path.join(new_dir, alarm_mapname)}")
        elif len(CONFIRMED_ALARMS) > 0:
            logger.error(f"{('Looked for ' + alarm_mapname + ' but found') if alarm_mapname else 'Found'} no alarm map to move although there should have been alarms exported!") 

        # Move log file
        update_logfile(os.path.join(new_dir, BASENAME_FILES))

    except Exception as e:
        logger.error(f"Failed to move files to their respective directory after a finished run: {e}")


""" 
### Main functions for both script states (LabInitialization and LabControl) as well as required Textualize UI components
"""

class YesNoScreen(ModalScreen[bool]):
    def __init__(self, prompt: str):
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(self.prompt, id="question"),
            Button("Yes", variant="primary", id="yes"),
            Button("No", variant="primary", id="no"),
            id="dialog",
        )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "yes":
            self.dismiss(True)
        else:
            self.dismiss(False)

class OkScreen(ModalScreen):
    def __init__(self, prompt: str):
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(self.prompt, id="question"),
            Button("ok", variant="primary", id="ok"),
            id="dialog",
        )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.dismiss()

class StringInputScreen(ModalScreen[str]):
    def __init__(self, prompt: str, allow_empty: bool = False):
        super().__init__()
        self.prompt = prompt
        self.allow_empty = allow_empty
        self.error_msg = ""

    def compose(self) -> ComposeResult:
        if self.error_msg:
            yield Static(self.error_msg, style="bold red")
        yield Static(self.prompt)
        yield Input(placeholder="Enter text:")

    def on_input_submitted(self, message: Input.Submitted) -> None:
        value = message.value.strip()
        if not self.allow_empty and not value:
            self.error_msg = "Input cannot be empty."
            self.refresh()
        else:
            self.dismiss(value)

class NumberInputScreen(ModalScreen[int]):
    def __init__(self, prompt: str, min_value: int = None, max_value: int = None, default_value: int = None, must_be_integer: bool = True):
        super().__init__()
        self.prompt = prompt
        self.min_value = min_value
        self.max_value = max_value
        self.default_value = default_value
        self.must_be_integer = must_be_integer
        self.error_msg = ""

    def compose(self) -> ComposeResult:
        if self.error_msg:
            yield Static(self.error_msg, style="bold red")
        yield Static(self.prompt)
        yield Input(placeholder="Enter a number", value=str(self.default_value) if self.default_value else None, type="integer" if self.must_be_integer else "number")

    def on_input_submitted(self, message: Input.Submitted) -> None:
        try:
            value = int(message.value.strip())
            if (self.min_value is not None and value < self.min_value) or \
               (self.max_value is not None and value > self.max_value):
                self.error_msg = f"Please enter a number between {self.min_value} and {self.max_value}."
                self.refresh()
            else:
                self.dismiss(value)
        except ValueError:
            self.error_msg = "Invalid input. Please enter an integer."
            self.refresh()

class SetVariableDelayDisplay_Helper_ManualTries(Screen):
    def __init__(self):
        super().__init__()
        self.error_msg = ""

    def compose(self) -> ComposeResult:
        if self.error_msg:
                yield Static(self.error_msg, style="bold red")
        yield Input(placeholder="Enter new number of tries until the delay is incremented:")

    def on_input_submitted(self, message: Input.Submitted) -> None:
        try:
            if int(message.value.strip()) > 0:
                self.dismiss(int(message.value.strip()))
            else:
                self.error_msg = "Invalid input. Please enter a positive integer."
        except ValueError:
            self.error_msg = "Invalid input. Please enter an integer."

class SetVariableDelayDisplay_Helper_ManualDelay(Screen):
    def __init__(self):
        super().__init__()
        self.error_msg = ""

    def compose(self) -> ComposeResult:
        if self.error_msg:
                yield Static(self.error_msg, style="bold red")
        yield Input(placeholder="Enter new step size in ms in which the delay is incremented:")

    def on_input_submitted(self, message: Input.Submitted) -> None:
        try:
            if int(message.value.strip()) > 0:
                self.dismiss(int(message.value.strip()))
            else:
                self.error_msg = "Invalid input. Please enter a positive integer."
        except ValueError:
            self.error_msg = "Invalid input. Please enter an integer."

class SetVariableDelayDisplay_Helper_Accept(ModalScreen[bool]):
    def __init__(self, manual_tries, manual_delay, new_tries_per_position, expected_time_ms):
        super().__init__()
        self.error_msg = ""
        self.manual_tries = manual_tries
        self.manual_delay = manual_delay
        self.new_tries_per_position = new_tries_per_position
        self.expected_time_ms = expected_time_ms

    def compose(self) -> ComposeResult:
        if self.error_msg:
            yield Static(self.error_msg, style="bold red")

        yield Static(
            f"These settings will lead to {self.new_tries_per_position} tries per position. "
            f"Given the stepsize and boundaries, we expect a runtime of {self.expected_time_ms / 1000 / 60 / 60:.1f}h."
        )

        yield Grid(
            Label("Do you want to use these values?", id="question"),
            Button("Yes", variant="primary", id="yes"),
            Button("No", variant="primary", id="no"),
            id="dialog",
        )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


class SetVariableDelayDisplay(ModalScreen[int]):
    """A modal screen for setting variable delay parameters."""

    def __init__(self):
        super().__init__()
        self.manual_tries = None
        self.manual_delay = None
        self.new_tries_per_position = None
        self.expected_time_ms = None

    def compose(self) -> ComposeResult:
        yield Static(
            f"We were given the following set of parameters:\n"
            f"- Tries per position: {TRIES_PER_POSITION}\n"
            f"- Estimated runtime of generating one RSA signature: {EXPECTED_DURATION_SIG_GEN_ms}ms\n"
            f" Therefore, we recommend the following settings for variable delay of the fault injection:\n"
            f"- Number of tries until the delay is incremented: {NO_OF_TRIES_PER_DELAY_INCREMENT}\n"
            f"- Step size in which the delay is incremented: {DELAY_INCREMENT_in_ms}ms\n"
            f"Confirm these settings by hitting enter. Otherwise, submit 'c' to change them manually or 'd' to disable varying delay for this run.",
        )
        yield Grid(
            Label("How to proceed?", id="question"),
            Button("Use these settings", variant="primary", id="accept"),
            Button("Set values manually", variant="primary", id="set-manually"),
            Button("Disable variable delay", variant="primary", id="disable"),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "accept":
            logger.info(f"User accepted the following values regarding a variable delay:")
            logger.info(f"- Tries per position: {TRIES_PER_POSITION}")
            logger.info(f"- Estimated runtime of generating one RSA signature: {EXPECTED_DURATION_SIG_GEN_ms} ms")
            logger.info(f"As a result, the following has been set:")
            logger.info(f"- Number of tries until the delay is incremented: {NO_OF_TRIES_PER_DELAY_INCREMENT}")
            logger.info(f"- Step size in which the delay is incremented: {DELAY_INCREMENT_in_ms} ms")
            self.dismiss()
            
        elif event.button.id == "set-manually":
            def accept(choice: bool | None) -> None:
                if choice:
                    global NO_OF_TRIES_PER_DELAY_INCREMENT, DELAY_INCREMENT_in_ms, TRIES_PER_POSITION, TRIES_LEFT_PER_POSITION, TRIES_LEFT_PER_POSITION_AND_TIME

                    NO_OF_TRIES_PER_DELAY_INCREMENT = self.manual_tries
                    TRIES_LEFT_PER_POSITION_AND_TIME = NO_OF_TRIES_PER_DELAY_INCREMENT

                    DELAY_INCREMENT_in_ms = self.manual_delay
                    TRIES_PER_POSITION = self.new_tries_per_position
                    TRIES_LEFT_PER_POSITION = TRIES_PER_POSITION
                    logger.info(f"User set the following values regarding a variable delay:")
                    logger.info(f"- Tries per position: {TRIES_PER_POSITION}")
                    logger.info(f"- Estimated runtime of generating one RSA signature: {EXPECTED_DURATION_SIG_GEN_ms} ms")
                    logger.info(f"As a result, the following has been set:")
                    logger.info(f"- Number of tries until the delay is incremented: {NO_OF_TRIES_PER_DELAY_INCREMENT}")
                    logger.info(f"- Step size in which the delay is incremented: {DELAY_INCREMENT_in_ms} ms")
                    self.dismiss()
                else:
                    self.app.push_screen(SetVariableDelayDisplay_Helper_ManualTries(), set_tries)

            def set_delay(manual_delay: int | None) -> None:
                self.manual_delay = manual_delay
                self.new_tries_per_position = int(EXPECTED_DURATION_SIG_GEN_ms // self.manual_delay * self.manual_tries)
                self.expected_time_ms = self.new_tries_per_position * EXPECTED_DURATION_SIG_GEN_ms  # TOTAL_PROGRESS is not available here
                self.app.push_screen(SetVariableDelayDisplay_Helper_Accept(self.manual_tries, self.manual_delay, self.new_tries_per_position, self.expected_time_ms), accept)

            def set_tries(manual_tries: int | None) -> None:
                self.manual_tries = manual_tries
                self.app.push_screen(SetVariableDelayDisplay_Helper_ManualDelay(), set_delay)

            self.app.push_screen(SetVariableDelayDisplay_Helper_ManualTries(), set_tries)

        elif event.button.id == "disable":
            global VARIABLE_DELAY
            VARIABLE_DELAY = False
            logger.info("Disabled variable delay for this run.")
            self.dismiss()

class LoadCheckpointDisplay(ModalScreen):
    """A modal screen for setting variable delay parameters."""

    def __init__(self, checkpoints, axes):
        super().__init__()
        self.checkpoints = checkpoints
        AXES = axes
        self.msg = "Found the following checkpoint files:\n" + "\n".join(
            f"  [{idx}] {fname} (from {ctime})" for idx, (fname, ctime) in enumerate(checkpoints)
        )

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"{self.msg}\nHow to proceed?", id="question"),
            Button("Load a checkpoint and continue from it", variant="primary", id="load"),
            Button("Evaluate a checkpoint as finished and quit", variant="primary", id="evaluate"),
            Button("Start new test without loading", variant="primary", id="start"),
            Button("Discard all checkpoints and start a new test", variant="primary", id="discard"),
            id="dialog",
        )

    def select_and_load_checkpoint(self):

        def callback(sel: int | None) -> None:
            global BOUNDARIES, CURRENT_POSITION, REFERENCE_POINT, TRIES_LEFT_PER_POSITION, CONFIRMED_FAULTS, CONFIRMED_ALARMS, PAST_TIMINGS, CHECKPOINT_FILE, TARGET_NAME, CURRENT_PROGRESS, TOTAL_PROGRESS, SIGNATURES_PARAMS, STARTING_POSITION

            fname = self.checkpoints[int(sel)][0]
            with open(fname, "rb") as f:
                checkpoint = pickle.load(f)

            # Restore variables
            BOUNDARIES = checkpoint["BOUNDARIES"]
            CURRENT_POSITION = checkpoint["CURRENT_POSITION"]
            REFERENCE_POINT = checkpoint["REFERENCE_POINT"]
            STARTING_POSITION = checkpoint["CURRENT_POSITION"]
            TRIES_LEFT_PER_POSITION = checkpoint["TRIES_LEFT_PER_POSITION"]
            CONFIRMED_FAULTS = checkpoint["CONFIRMED_FAULTS"]
            CONFIRMED_ALARMS = checkpoint["CONFIRMED_ALARMS"]
            PAST_TIMINGS = checkpoint["PAST_TIMINGS"]
            CURRENT_PROGRESS = checkpoint["CURRENT_PROGRESS"]
            TOTAL_PROGRESS = checkpoint["TOTAL_PROGRESS"]
            TARGET_NAME = checkpoint["TARGET_NAME"]
            CHECKPOINT_FILE = fname
            update_logfile("_".join(str(fname[:-4]).split("_")[:-1]))
            
            logger.info(f"Loaded checkpoint {fname} from {checkpoint.get('checkpoint_time','unknown')}")
        
        if len(self.checkpoints) == 1:
            callback(0)
        else:
            self.app.push_screen(
                NumberInputScreen(
                    f"Enter checkpoint number (0-{len(self.checkpoints)-1}):",
                    min_value=0,
                    max_value=len(self.checkpoints)-1
                ),
                callback
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load":
            self.select_and_load_checkpoint()
            self.dismiss(True)
            
        elif event.button.id == "evaluate":
            self.select_and_load_checkpoint()
            export_faults_and_map()
            self.app.call_from_thread(self.app.exit, 0)

        elif event.button.id == "start":
            self.dismiss(False)

        elif event.button.id == "discard":
            for fname, _ in self.checkpoints:
                try:
                    os.remove(fname)
                    logger.info(f"Checkpoint deleted: {fname}")
                except Exception as e:
                    logger.info(f"Failed to delete checkpoint {fname}: {e}")
            self.dismiss(False)   

class PositionInputScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Set new position for X and Y axes. Submit to move and stay at these coordinates", id="title"),
            Label("X-Position", id="name-1"),
            Input(placeholder="X-Position in mm...", value=str(CURRENT_POSITION["X"]) if CURRENT_POSITION["X"] is not None else None, id="x-position", type="number"),
            Label("Y-Position", id="name-2"),
            Input(placeholder="Y-Position in mm...", value=str(CURRENT_POSITION["Y"]) if CURRENT_POSITION["Y"] is not None else None, id="y-position", type="number"),
            Button("Submit", id="submit")
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            global ALLOW_MOVEMENT
            try:
                x_input = float(self.query_one("#x-position", Input).value)
                y_input = float(self.query_one("#y-position", Input).value)
                logger.info(f"User provided new position: X={x_input}, Y={y_input}")
            except ValueError:
                logger.error("Invalid input for X or Y position. Please enter valid numbers.")
                ALLOW_MOVEMENT = True
                return
            
            if x_input and BOUNDARIES["X"]["LEFT"] >= x_input >= BOUNDARIES["X"]["RIGHT"] and y_input and BOUNDARIES["Y"]["UP"] >= y_input >= BOUNDARIES["Y"]["DOWN"]:
                move(AXES, {"X": float(x_input), "Y": float(y_input)}, overwrite=True)
                logger.info(f"Allow movement = {ALLOW_MOVEMENT}")
            else:
                logger.error(f"Did not follow user-provided movement commands as they were out of bounds: {x_input} mm (X), {y_input} mm (Y)")
                ALLOW_MOVEMENT = True

            logger.info(f"Allow movement = {ALLOW_MOVEMENT}")
            self.app.pop_screen()

class LabInitialization(App):
    def __init__(self):
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Container(
            Log(id="system_log", highlight=True),
            id="main_container"
        )

    def action_emergency_stop(self, axes=AXES) -> None:
        logger.error("Emergency stop triggered by user. Stopping motors and all operations.")
        for axis, motor in axes.items():
            try:
                motor.stop(immediate=True, sync=False)
                logger.info(f"Stopped {axis} axis")
            except Exception as e:
                logger.error(f"Failed to stop {axis} axis: {e}")
        raise Exception("Emergency stop triggered by user. Exiting application.")

    @work
    async def on_mount(self) -> None:
        global CHIPSHOUTER_PORT, TARGET_PORT, TARGET_NAME, CHECKPOINT_FILE
        global DELAY_INCREMENT_in_ms, NO_OF_TRIES_PER_DELAY_INCREMENT, TRIES_PER_POSITION, TRIES_LEFT_PER_POSITION, TRIES_LEFT_PER_POSITION_AND_TIME, VARIABLE_DELAY
        global AXES, CS, ARDUINO_PORT
        global BOUNDARIES_FILE
        global STEP_SIZE

        # Setup logging to Textual
        log_buffer = []

        class BufferingHandler(logging.Handler):
            def emit(self, record):
                msg = self.format(record)
                if not msg.endswith('\n'):
                    msg += '\n'
                log_buffer.append(self.format(record))

        formatter = logging.Formatter("[%(asctime)s] | %(levelname)-7s | %(message)s", datefmt="%m/%d/%y %H:%M:%S")

        buffer_handler = BufferingHandler()
        buffer_handler.setFormatter(formatter)
        logger.addHandler(buffer_handler)

        logger.debug("The following devices are connected:")
        for port in serial.tools.list_ports.comports():
            logger.debug(f"- Port: {port.device}, Description: {port.description}, Serial Number: {port.serial_number}")

        if args.dryrun:
            logger.warning("Dryrun: Set fake COM Ports")
            CHIPSHOUTER_PORT = "/dev/fakeUSB0"
            if AUTO_RESET_TARGET:
                ARDUINO_PORT = "/dev/fakeUSB2"

        else:
            logger.info("Looking for COM Ports...")
            CHIPSHOUTER_PORT = find_tty_path(CHIPSHOUTER_SERIAL_NUMBER)
            if AUTO_RESET_TARGET:
                ARDUINO_PORT = find_tty_path(ARDUINO_SERIAL_NUMBER)

        if args.dryrun and not args.realtarget:
            TARGET_PORT = "/dev/fakeUSB1"
        else:
            TARGET_PORT, TARGET_NAME = find_tty_path(TARGET_SERIAL_NUMBERS)
            TARGET_PORT, TARGET_NAME = find_tty_path(TARGET_SERIAL_NUMBERS)

        if not TARGET_PORT:
            stop_event.set()
            raise Exception("Error finding target port")
        

        AXES = await init_axes(app=self)

        if (not AXES):
            raise Exception("Initializing axes returned no axes. Please check your setup.")
        
        if args.jogonly:       
            await self.push_screen_wait(JogInteractively(AXES, "Jog-only mode. Move the axes however you like and quit by submitting."))
            raise Exception("Jogging mode only. Exiting application.")

        
        CS = CS_Connector(CHIPSHOUTER_PORT)

        if (not CS):
            raise Exception("Initializing the ChipSHOUTER returned no object. Please check your setup.")
        
        if args.noinit:
            self.app.exit(log_buffer)

        if args.dryrun and not args.realtarget:
            logger.info("Dry-run: Using fake target emulator")
            global DUMMY_TARGET
            DUMMY_TARGET = DummyTarget(delay=1, reset_enabled=False, faults_enabled=True) #, start_on_error=24, reset_enabled=True, deterministic_errors=True)

        # Confirm Tip Parameters
        if args.quickdebug:
            response = True
        else:
            response = await self.push_screen_wait(YesNoScreen(
                f"Is the following tip attached?\n - Diameter: {TIP_USED.get('diameter_mm', 'unknown')}mm\n - Winding: {TIP_USED.get('winding', 'unknown')}"
            ))
        if not response:
            TIP_USED["diameter_mm"] = await self.push_screen_wait(
                NumberInputScreen(
                    "Enter the tip diameter in mm",
                    min_value=0,
                    default_value=TIP_USED.get("diameter_mm", 0),
                    must_be_integer=False
                )
            )
            TIP_USED["winding"] = await self.push_screen_wait(
                StringInputScreen(
                    "Enter the tip winding (e.g. 'CW' or 'CCW')",
                    allow_empty=False
                )
            )
            if not float(TIP_USED["diameter_mm"]) == float(STEP_SIZE):
                await self.push_screen_wait(YesNoScreen(
                    f"The step size is currently set to {STEP_SIZE}mm. Do you want to update it to {TIP_USED['diameter_mm']}mm?"
                ))
                try:
                    STEP_SIZE = float(TIP_USED["diameter_mm"])
                except Exception as e:
                    logger.error(f"Could not update step size to tip diameter (which is of type {type(TIP_USED['diameter_mm'])} with value {TIP_USED['diameter_mm']}): {e}")

        logger.info(f"Using tip with diameter {TIP_USED['diameter_mm']}mm and winding {TIP_USED['winding']}")
        BOUNDARIES_FILE = f"{TIP_USED['diameter_mm']}-{TIP_USED['winding']}-tip_{BOUNDARIES_FILE}"

        checkpoints = list_checkpoints()
        if checkpoints and not args.quickdebug:
            adjustment_needed = await self.push_screen_wait(LoadCheckpointDisplay(checkpoints, AXES))
            if adjustment_needed:
                await self.app.push_screen_wait(LoadBoundariesDisplay(AXES))

        if not CHECKPOINT_FILE:

            if not TARGET_NAME:
                if args.quickdebug:
                    TARGET_NAME = "quicktest"

                else:    
                    TARGET_NAME = await self.push_screen_wait(
                        StringInputScreen(
                            "Enter a target name (optional)",
                            allow_empty = True
                        )
                    )

            if TARGET_NAME:
                update_logfile(BASENAME_FILES + "_" + TARGET_NAME)
                # logger.info(f"Set target name to: {TARGET_NAME}")
                BOUNDARIES_FILE = f"{TARGET_NAME}_{BOUNDARIES_FILE}"

            else:
                logger.info(f"Did not provide a target name. Omitting it in file-writes")
            
            CHECKPOINT_FILE = f"{BASENAME_FILES}_checkpointv4.pkl"

        await setBoundaries(AXES, self)
            
        if VARIABLE_DELAY and not args.quickdebug:
            DELAY_INCREMENT_in_ms, NO_OF_TRIES_PER_DELAY_INCREMENT = calculate_variable_delay_profile()
            await self.push_screen_wait(SetVariableDelayDisplay())

        verifyParameters()  

        self.app.exit(log_buffer)

class StatusDisplay(Static):
    def update_status(self):
        self.update(
            f"{'STOPPED' if stop_event.is_set() else 'RUNNING'} | CS: {'ON' if CS.enabled else 'OFF'} | Target state: {TARGET.target_state.name}\n"
            f"Voltage: {FAULT_VOLTAGE:.2f} V | Deadtime: {DEAD_TIME} ms | Variable: Delay ({'ON' if VARIABLE_DELAY else 'OFF'}) Voltage ({'ON' if VARIABLE_VOLTAGE else 'OFF'}) High Time ({'ON' if VARIABLE_HIGH_TIME else 'OFF'})\n"
            f"Total Signatures: {SIG_COUNTER} | Parseable: {TARGET.number_of_signatures} | Unparseable: {TARGET.number_of_unparseables} | With faults: {len(CONFIRMED_FAULTS)} | With alarms: {len(CONFIRMED_ALARMS)} | Tries left on Position: {TRIES_LEFT_PER_POSITION} / {TRIES_PER_POSITION} | Moved {POS_COUNTER} / {STEPS_REQUIRED}\n" 
        )
class LabControl(App):
    BINDINGS = [
        ("e (x2)", "emergency_stop", "E-STOP"),
        ("z", "toggle_uart", "Toggle UART"),
        ("u", "toggle_debug", "Toggle Debug"),
        ("a", "set_voltage", "Set Voltage"),
        ("s", "set_pulse_high_time", "Set High-time"),
        ("d", "set_deadtime", "Set Dead-time"),
        ("f", "toggle_variable_voltage", "Var. Voltage"),
        ("g", "toggle_variable_pattern", "Var. High Time"),
        ("h", "get_detail_cs", "Get CS Details"),
        ("j", "selfheal_CS", "Selfheal CS"),
        ("k", "reset_CS", "Reset CS"),
        ("l", "disable_CS", "Dis-/Enable CS"),
        ("w", "set_tries_per_position", "Set No. of Tries"),
        ("r", "set_position", "Position overwrite"),
        ("t", "get_position", "Get position"),
        ("x", "reset_target", "Reset Target"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, old_logs):
        super().__init__()
        
        self.old_logs = old_logs
        self.is_shutdown = False
        self._e_stop_sequence = []
        self.log_widget = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Log(id="system_log", highlight=True),
            ProgressBar(id="progress", show_eta=True),
            StatusDisplay(id="status"),
            id="main_container"
        )
        yield Footer()

    def on_key(self, event):
        # Detect double "e" press within 1 second
        now = time.time()
        self._e_stop_sequence = [
            (k, t) for k, t in self._e_stop_sequence if now - t < 1.0
        ]
        if event.key.lower() == "e":
            self._e_stop_sequence.append(("e", now))
            if len([k for k, _ in self._e_stop_sequence if k.lower() == "e"]) >= 2:
                self.action_emergency_stop()
                self._e_stop_sequence.clear()

        elif event.key.lower() == "x":
            self._e_stop_sequence.append(("x", now))
            if len([k for k, _ in self._e_stop_sequence if k.lower() == "x"]) >= 2:
                self.action_force_reset_target()
                self._e_stop_sequence.clear()
        else:
            self._e_stop_sequence.clear()

         
    def on_mount(self) -> None:
        global CHIPSHOUTER_PORT, TARGET_PORT
        global DELAY_INCREMENT_in_ms, NO_OF_TRIES_PER_DELAY_INCREMENT, TRIES_PER_POSITION, TRIES_LEFT_PER_POSITION, TRIES_LEFT_PER_POSITION_AND_TIME, VARIABLE_DELAY, TOTAL_PROGRESS, STEPS_REQUIRED
        global AXES, CS, TARGET

        # Setup logging to Textual
        self.log_widget = self.query_one("#system_log")

        for line in self.old_logs:
            self.log_widget.write(line + "\n")
        
        class TextualHandler(logging.Handler):
            def __init__(self, log_widget):
                super().__init__()
                self.log_widget = log_widget

            def emit(self, record):
                # Ensure message ends with newline
                msg = self.format(record)
                if not msg.endswith('\n'):
                    msg += '\n'
                self.log_widget.write(msg)

        handler = TextualHandler(self.log_widget)
        formatter = logging.Formatter("[%(asctime)s] | %(levelname)-7s | %(message)s", datefmt="%m/%d/%y %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Schedule regular UI updates
        self.set_interval(EXPECTED_DURATION_SIG_GEN_ms/1000, self.update_ui)

        logger.info("Moving to starting position")

        if STARTING_POSITION:
            move(AXES, {"Z": 0, "X": STARTING_POSITION.get("X"), "Y": STARTING_POSITION.get("Y")})
        else:
            move(AXES, {"Z": 0, "X": BOUNDARIES["X"]["LEFT"], "Y": BOUNDARIES["Y"]["UP"]})
        move(AXES, {"Z": BOUNDARIES["Z"]["DOWN"]})

        STEPS_REQUIRED = int(( (BOUNDARIES["X"]["LEFT"] - BOUNDARIES["X"]["RIGHT"] + 1) // STEP_SIZE ) * ( (BOUNDARIES["Y"]["UP"] - BOUNDARIES["Y"]["DOWN"] + 1) // STEP_SIZE ))
        TOTAL_PROGRESS = STEPS_REQUIRED * TRIES_PER_POSITION
        logger.info(f"Starting with {CURRENT_PROGRESS} of {TOTAL_PROGRESS} tries.")
        store_positions(AXES)

        TARGET = SerialTarget(TARGET_PORT, TARGET_BAUDRATE, "TARGET", event_queue, stop_event)

        # Start background threads
        logger.info("Starting target listener thread")
        self.target_thread = threading.Thread(
            target=TARGET.listen
        )
        self.target_thread.start()

        logger.info("Starting worker thread")
        self.worker_thread = threading.Thread(
            target=self.worker_loop
        )
        self.worker_thread.start()

        CS.change(voltage=FAULT_VOLTAGE_START, deadtime=DEAD_TIME_START)

        stat = os.statvfs('.')
        available_space = stat.f_bavail * stat.f_frsize
        
        if available_space < (10 * 1024**3):
            logger.warning(f"Less than 10 GB of disk space! Available: {available_space / (1024**3):.1f} GB")
        else:
            logger.info(f"Available disk space: {available_space / (1024**3):.1f} GB")

        try:
            TARGET.reset()
        except Exception as e:
            logger.info("Setup finished but failed to reset target. Plug in target now, if not done already, and then arm the ChipShouter manually")
            logger.debug(f"Error resetting target: {e}")
        else:
            logger.info("Setup finished.")
        
    def update_ui(self):
        progress_bar = self.query_one("#progress")
        status_display = self.query_one("#status")
        try:
            progress_bar.update(total=TOTAL_PROGRESS,progress=CURRENT_PROGRESS)
            status_display.update_status()

        except Exception as e:
            tb = traceback.extract_tb(e.__traceback__)
            if tb:
                filename, lineno, func, text = tb[-1]
                logger.error(f"Failed to update UI: {filename} raised an error on line {lineno} (func {func}): {text}\n{e}")
            else:
                logger.error(f"Failed to update UI:\n{e}")  

    def worker_loop(self):
        global CURRENT_PROGRESS, CONFIRMED_FAULTS, AXES, CS
        timeout_counter = 0

        def handleException():
            global CS
            try:
                print("Exception handling in worker_loop triggered. Resetting target, motors, and ChipShouter...")

                if TARGET:
                    TARGET.reset()

                selfheal_axes()
                CS.selfheal()

            except Exception as e:
                tb = traceback.extract_tb(e.__traceback__)
                if tb:
                    filename, lineno, func, text = tb[-1]
                    logger.error(f"Handling worker_loop exception failed with {type(e)}: {filename} raised an error on line {lineno} (func {func}): {text} ('{e}'). Exiting application.")
                else:
                    logger.error(f"Handling worker_loop exception failed with {type(e)} ({e}). Exiting application.")
                export_params()
                save_checkpoint()
                stop_event.set()
                self.call_from_thread(self.action_quit, force=True)
                return
        
        try:

            while not stop_event.is_set():
                # logger.debug("Heartbeat from worker-loop")
                try:
                    device, keyword, payload_str, sig_params = event_queue.get(timeout=EXPECTED_DURATION_SIG_GEN_ms/1000*3)
                    if device is None and keyword is None and payload_str is None:
                        continue  # Check stop_event on sentinel

                except queue.Empty:
                    timeout_counter += 1
                    if timeout_counter > 100:
                        logger.warning("Event queue is empty for a long time. This might indicate a problem with the target, resetting it.")
                        TARGET.reset()
                        timeout_counter = 0
                    continue

                except Exception as e:
                    logger.error(f"{type(e)} while getting from event queue: {e}. Resetting all hardware.")
                    handleException()
                    continue

                # Print UART communication
                if SHOW_UART:
                    logger.info(f"{device} | {keyword} {payload_str}")

                if keyword in KEYWORD_HANDLERS and device in KEYWORD_HANDLERS[keyword]:

                    # logger.debug(f"Worker loop received keyword: {keyword}.")

                    # Execute the handler for the keyword
                    try:
                        finished_state = KEYWORD_HANDLERS[keyword][device](payload_str, sig_params)
                        if finished_state == True:
                            self.action_quit(force=True)

                    except Exception as e:
                        logger.error(f"Worker loop caught an {type(e)} ({e}) by the handler for keyword '{keyword}'. Initializing selfheal.")
                        handleException()

                else:
                    logger.warning(f"{device} sent unexpected keyword: {keyword}.")      
            
        except Exception as e:
            save_checkpoint()
            tb = traceback.extract_tb(e.__traceback__)
            if tb:
                filename, lineno, func, text = tb[-1]
                logger.error(f"Error in worker_loop: {filename} raised an error on line {lineno} (func {func}): {text}\n{e}")
            else:
                logger.error(f"Error in worker_loop:\n{e}")  
        
        else:
            export_faults_and_map()

        finally:
            if stop_event.is_set():
                export_params()
                self.call_from_thread(self.action_quit)

    """ The following actions are executed upon user request through the UI. Some, e.g., emergency_stop or quit, can also be triggered by the script. """

    def action_emergency_stop(self) -> None:
        logger.error("Emergency stop triggered by user. Stopping motors and all operations.")
        for axis, motor in AXES.items():
            try:
                motor.stop(immediate=True, sync=False)
                logger.info(f"Stopped {axis} axis")
            except Exception as e:
                logger.error(f"Failed to stop {axis} axis: {e}")

        self.action_quit(force=True)

    def action_reset_target(self) -> None:
        if TARGET.target_state != OperationalState.NORMAL and TARGET.target_state != OperationalState.CS_DISABLED and TARGET.target_state != OperationalState.TRYING_BAUDRATES:
            logger.info("Target is already resetting. Double-click hotkey to overwrite.")
        else:
            logger.info("Resetting target per user request.")
            TARGET.reset()

    def action_force_reset_target(self) -> None:
        global TARGET
        logger.info("Force resetting target per user request.")
        TARGET.target_state = OperationalState.NORMAL
        TARGET.reset()

    def action_reset_CS(self) -> None:
        logger.info("Resetting ChipShouter per user request.")
        CS.reset()

    def action_disable_CS(self) -> None:
        if "user_request" in CS.disable_requests:
            logger.info("Enabling ChipShouter per user request.")
            CS.release_disable("user_request")

        else:
            logger.info("Disabling ChipShouter per user request.")
            CS.request_disable("user_request")

    def action_selfheal_CS(self) -> None:
        logger.info("Selfhealing ChipShouter per user request.")
        CS.selfheal()

    def action_toggle_uart(self) -> None:
        global SHOW_UART
        SHOW_UART = not SHOW_UART
        logger.info(f"showUART = {SHOW_UART}")

    def action_toggle_debug(self) -> None:
        global DEBUG, logger, file_handler
        DEBUG = not DEBUG
        logger.setLevel(logging.DEBUG) if DEBUG else logger.setLevel(logging.INFO)
        file_handler.setLevel(logging.DEBUG) if DEBUG else file_handler.setLevel(logging.INFO)
        logger.info(f"DEBUG = {DEBUG}")

    def action_toggle_variable_voltage(self) -> None:
        global VARIABLE_VOLTAGE, FAULT_VOLTAGE
        VARIABLE_VOLTAGE = not VARIABLE_VOLTAGE
        if not VARIABLE_VOLTAGE:
            FAULT_VOLTAGE = FAULT_VOLTAGE_START
        logger.info(f"Variable voltage = {VARIABLE_VOLTAGE}")

    def action_toggle_variable_pattern(self) -> None:
        global VARIABLE_HIGH_TIME, FAULT_PATTERN
        VARIABLE_HIGH_TIME = not VARIABLE_HIGH_TIME
        if not VARIABLE_HIGH_TIME:
            FAULT_PATTERN = FAULT_PATTERN_START
        logger.info(f"Variable high time = {VARIABLE_HIGH_TIME}")
        
    def action_set_position(self) -> None:
        global ALLOW_MOVEMENT
        if not ALLOW_MOVEMENT:
            ALLOW_MOVEMENT = True
            logger.info(f"Allow movement = {ALLOW_MOVEMENT}")
        else:
            ALLOW_MOVEMENT = False
            self.app.push_screen(PositionInputScreen())
        store_positions(AXES)

    def action_get_position(self) -> None:
        x_pos = AXES["X"].get_position()
        y_pos = AXES["Y"].get_position()
        z_pos = AXES["Z"].get_position()

        logger.info("Current position is:")
        logger.info(f" - X: {x_pos} mm abs ({x_pos  - REFERENCE_POINT['X']} mm)")
        logger.info(f" - Y: {y_pos} mm abs ({y_pos  - REFERENCE_POINT['Y']} mm)")
        logger.info(f" - Z: {z_pos} mm abs")

    def action_set_voltage(self) -> None:
        def callback(new_voltage: int | None) -> None:
            if new_voltage is not None and new_voltage != FAULT_VOLTAGE:
                global FAULT_VOLTAGE_START, FAULT_VOLTAGE_START_AT_STEP
                FAULT_VOLTAGE_START = new_voltage
                FAULT_VOLTAGE_START_AT_STEP = new_voltage
                CS.change(voltage=new_voltage)
        self.app.push_screen(
            NumberInputScreen(
                f"Change Voltage. A valid voltage is an integer between {MIN_VOLTAGE} and {MAX_VOLTAGE}:",
                min_value=MIN_VOLTAGE,
                max_value=MAX_VOLTAGE,
                default_value=FAULT_VOLTAGE
            ),
            callback
        )

    def action_set_deadtime(self) -> None:
        def callback(new_deadtime: int | None) -> None:
            if new_deadtime is not None:
                CS.change(deadtime=new_deadtime)
        self.app.push_screen(
            NumberInputScreen(
                f"Change deadtime in ms. A valid dead-time is an integer between 1 and 1000:",
                min_value=1,
                max_value=1000,
                default_value=DEAD_TIME
            ),
            callback
        )

    def action_set_pulse_high_time(self) -> None:
        def callback(new_high_time: int | None) -> None:
            if new_high_time is not None and new_high_time != sum(1 for x in FAULT_PATTERN if x == 1) * MIN_HIGH_TIME_ns:
                CS.change(timeHigh_ns=new_high_time)
            else:
                logger.error("Invalid high time value. High time must be a multiple of 20ns and within the allowed range.")
        self.app.push_screen(
            NumberInputScreen(
                f"Change the pulse high time in nanoseconds. Longer pulses create a shorter delay before the pulse. High time can only be changed in 20ns increments",
                min_value=0,
                max_value=MAX_HIGH_TIME_ns,
                default_value=sum(1 for x in FAULT_PATTERN if x == 1) * 20
            ),
            callback
        )

    def action_set_tries_per_position(self) -> None:
        def callback(new_tries: int | None) -> None:
            global TRIES_PER_POSITION, TRIES_LEFT_PER_POSITION, TOTAL_PROGRESS
            if new_tries is not None and new_tries != TRIES_PER_POSITION:
                TOTAL_PROGRESS = TOTAL_PROGRESS - (STEPS_REQUIRED - POS_COUNTER) * TRIES_PER_POSITION + (STEPS_REQUIRED - POS_COUNTER) * new_tries
                TRIES_PER_POSITION = new_tries
                if TRIES_LEFT_PER_POSITION > TRIES_PER_POSITION:
                    TRIES_LEFT_PER_POSITION = TRIES_PER_POSITION
                logger.info(f"Set tries per position to {TRIES_PER_POSITION}.")
                if new_tries < 51:
                    logger.warning(f"Setting tries per position to {new_tries} is very low. The 'BAM BAM' paper found less than 2% success rate!")
        self.app.push_screen(
            NumberInputScreen(
                f"Change the number of tries per position.",
                min_value=1,
                max_value=None,
                default_value=TRIES_PER_POSITION
            ),
            callback
        )
    
    def action_get_detail_cs(self) -> None:
        try:
            cs_str = CS.getInfo()
        except Exception as e:
            logger.error(f"Caught {type(e)} while getting ChipSHOUTER details: {e}")
            return
        else:
            if cs_str is not None and isinstance(cs_str, str):
                self.app.push_screen(OkScreen(cs_str))
            else:
                logger.error("Failed to get CS Info.")

    def action_quit(self, force=False) -> None:

        def close_window():
            self.call_from_thread(self.exit)

        def cleanup():
            logger.info("Shutting down...")
            logger.info(f"Moved {POS_COUNTER} times and received {SIG_COUNTER} signatures. {TRIES_PER_POSITION} tries per position were configured.")
            stop_event.set()

            time.sleep(0.5)

            # Wait for threads to finish
            if hasattr(self, "target_thread"):
                self.target_thread.join()
            event_queue.put((None, None, None, None)) # Sentinel to unblock worker loop
            if hasattr(self, "worker_thread"):
                self.worker_thread.join()

            if AXES is None:
                logger.warning("No axes to deinitialize.")
            else:
                deinit_axes(AXES)
                

            if CS is None:
                logger.warning("No ChipSHOUTER to deinitialize.")
            else:
                try:
                    CS.arm(False, "shutdown")
                    CS.disconnect()
                except Exception as e:
                    logger.error(f"Failed to disconnect ChipSHOUTER: {e}")
                else:
                    logger.info("Disconnected ChipSHOUTER")
                

            if PAST_TIMINGS["between_trigger_and_signGen_ms"] and PAST_TIMINGS["trigger_duration_ns"]:
                logger.info(f"Recorded {len(PAST_TIMINGS['between_trigger_and_signGen_ms'])} shots")

                values = PAST_TIMINGS["between_trigger_and_signGen_ms"]
                mean_time = sum(values) / len(values)
                variance = sum((x - mean_time) ** 2 for x in values) / len(values)
                stddev = math.sqrt(variance)
                logger.info(f"Mean duration: {mean_time:.3f} ms, StdDev: {stddev:.3f} ms")

                values = PAST_TIMINGS["trigger_duration_ns"]
                mean_time = sum(values) / len(values)
                variance = sum((x - mean_time) ** 2 for x in values) / len(values)
                stddev = math.sqrt(variance)
                logger.info(f"Mean trigger duration: {mean_time:.3f} ns, StdDev: {stddev:.3f} ns")

            else:
                logger.info("No timings recorded yet.")

            logger.info("Finished cleanup. Exit this window by pressing Q.")
            self.is_shutdown = True
        
        if not stop_event.is_set():
            def callback(quit: bool | None) -> None:
                if quit:
                    threading.Thread(target=cleanup, daemon=True).start()

            if force:
                callback(True)
            else:
                if any("WARNING" in line or "ERROR" in line for line in self.log_widget.lines[-10:]):
                    self.app.push_screen(
                        YesNoScreen(f"There are warnings or errors in the log:\n\n{'\n'.join(self.log_widget.lines[-10:])}\n\nDo you want to quit?\n\n"),
                        callback
                    )
                else:
                    self.app.push_screen(
                        YesNoScreen("Do you want to quit?"),
                        callback
                    )
            
        # Exit the window on second "q"-press
        elif self.is_shutdown:
            threading.Thread(target=close_window, daemon=True).start()
             

def main():
    init_app = LabInitialization()
    log_buffer = init_app.run()
    
    if log_buffer:
        app = LabControl(log_buffer)
        app.run()
        print(f"Saved Logfile to {LOGFILE}")        

if __name__ == "__main__":
    main()
