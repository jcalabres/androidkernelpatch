#!/usr/bin/env python
#*******************************************************
#* Copyright (C) 2017 e0d1n & zh0kx
#*******************************************************

import os
import time
import sys
import tempfile
import shutil
import fileinput
import argparse

from datetime import datetime
from subprocess import Popen, check_output, STDOUT, PIPE 

ACTUAL_PATH = os.path.dirname(os.path.realpath(__file__));

TMP_FOLDER = os.path.join(ACTUAL_PATH,"tmp")
ADBD_PATH = os.path.join(ACTUAL_PATH,"adbd")
OUT = os.path.join(ACTUAL_PATH, "roms")

DESCRIPTION = '''Tool used to patch the boot kernel to always run adbd as root. Also removes ro.secure and enables ro.debuggable

made by: e0d1n & zh0kx | Only works in Linux based systems'''

USAGE = '''
   {HEADER}unpack{RESET}     Unpack the given rom .img file to a directory
   {HEADER}pack{RESET}       Packs the given directory folder to a .img file
   {HEADER}patch{RESET}      Patch a .img rom image or a given folder containing the extracted ramdisk files (unpack-patch-pack)
   {HEADER}flash{RESET}      Flash a binary .img rom to the connected device
   {HEADER}bootloader{RESET} Restarts the device in bootloader mode
   {HEADER}reboot{RESET}     Exits the bootloader mode
   {HEADER}doall{RESET}      Do all (unpack-patch-pack-flash)
   {HEADER}deps{RESET}       Automatically resolve deps (Only Debian for the moment)   

'''

class color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    RESET = "\033[0;0m"

def success(msg):
    print color.BOLD+color.OKGREEN+"[+] "+color.RESET + msg

def error(msg):
    print color.BOLD+color.FAIL+"[-] "+color.RESET + msg

def info(msg):
    lines = msg.splitlines()
    for line in lines:
        print color.BOLD+color.OKBLUE+"[i] "+color.RESET + line

def help(msg=None):
    VERSIONS = ['5.1.1','4.4.4']
    colorsdic = {'HEADER':color.HEADER,'RESET':color.RESET, 'BLUE': color.OKBLUE }
    print DESCRIPTION.format(**colorsdic)
    print
    info("Tested with versions: {}".format(', '.join(VERSIONS)))
    print USAGE.format(**colorsdic)
    if msg:
        error(msg)

def generate_version_name():
    if check_device():
        model = check_output('adb shell getprop ro.product.model'.split(' ')).strip().lower().replace(' ','_')
        name = check_output('adb shell getprop ro.product.device'.split(' ')).strip().lower().replace(' ','_')
        kernel = check_output('adb shell uname -r'.split(' ')).strip().lower().replace(' ','_')
        root = model+'_'+name+'_'+kernel+'_'+'root'
    else:
        root = "image_root"
    datestring = datetime.strftime(datetime.now(), '%Y-%m-%d-%H-%M-%S')
    fullname = root+'_'+datestring+'.img'
    return fullname

def replace_lines(file, what, to):
    if len(what) != len(to):
        raise ValueError("Received lists with different sizes")
    # Creates a temporary file
    fh, tmp_path = tempfile.mkstemp()
    # Open that file given a descriptor
    with os.fdopen(fh,'w') as new:
        # Open the old file where we want to replace text
        with open(file) as old:
            for line in old:
                found = False
                for w,t in zip(what,to):
                    if w in line:
                        # If text is found replace it with the new line
                        new.write(t.rstrip()+'\n')
                        found = True
                if not found:
                    # write the existing line
                    new.write(line)
    # Remove old file
    os.remove(file)
    # src,dst
    shutil.move(tmp_path,file)

def addline(file, line_to_add, where, bottom=True):
    buf = []
    with open(file, "r") as in_file:
	buf = in_file.readlines()

    with open(file, "w") as out_file:
	for line in buf:
	    if where in line:
                if bottom:
		    line = line + "\n{}\n".format(line_to_add)
                else:
		    line = "{}\n".format(line_to_add) + line
	    out_file.write(line)

def check(args,msg=None):
    if len(args) == 0:
        help(msg)
        return False
    return True

def check_tools():
    binaries = ["lz4", "mkboot", "mkbootfs", "mkbootimg", "sepolicy-inject"]
    for binary in binaries:
        if not os.path.isfile(os.path.join(ACTUAL_PATH,'tools', binary)):
            error("Tool {} not found".format(binary))
            sys.exit(1)

def get_path(args, default):
    destination_path = default
    if len(args) == 2:
        destination_path = args[1]
    return destination_path

def unpack(args):
    '''Usage: unpack rom_image [directory]'''
    check_tools()
    try:
        image = args[0]
    except:
        help(unpack.__doc__)
        sys.exit(1)
    if not os.path.isfile(image):
        error("Default image {} not found".format(ROM))
        sys.exit(1)
    directory = get_path(args, TMP_FOLDER)
    if not os.path.exists(image) or os.path.isdir(image):
	error("File not found: {}".format(image))
	sys.exit(1)
    out = check_output('file {}'.format(image).split(' '))
    if 'Android bootimg' not in out:
	error("File is not an android bootimg")
	sys.exit(1)
    out = check_output('tools/mkboot {} {}'.format(image, directory).split(' '))
    if "Unpack completed" in out:
	success("Unpacked on {}".format(directory))
	return directory
    else:
	error("Couldn't unpack the img {}".format(image))
	return None

def pack(args):
    '''usage: pack rom_folder [destination]'''
    check_tools()
    if not check(args, pack.__doc__):
        return 1
    else:
	rom = args[0]
        if not os.path.exists(rom):
            error("Rom folder not found")
            sys.exit(1)
        destination = ""
        destination_path = None
        if len(args) == 2:
            destination = args[1]
        if ".img" in destination:
            destination_name = os.path.basename(destination)
            destination_path = os.path.abspath(destination)
        elif os.path.isdir(destination):
            destination_name = generate_version_name()
            destination_path = os.path.join(destination, destination_name)
        else:
            destination_name = generate_version_name()
            destination_path = os.path.join(OUT, destination_name)

        if not os.path.exists(os.path.dirname(destination_path)):
            os.makedirs(os.path.dirname(destination_path))

	out = check_output('tools/mkboot {} {}'.format(rom, destination_path).split(' '))

	if 'has been created' in out:
	    success("Packed {} to {}{}{}".format(rom, color.BOLD, color.RESET , destination_path))
	    return destination_path
	else:
	    error("Couldn't pack {} to {}".format(rom, destination_path))
            return None

def do_patch(folder):
    # Set the default.prop file
    info("Disabling default.prop ro.secure/ro.adb.secure and selinux.reload_policy")
    prop = os.path.join(folder,'ramdisk/default.prop')

    replace_lines(prop,['ro.secure=1',
                        'ro.adb.secure=1',
                        'ro.debuggable=0'],
                       ['ro.secure=0',
                        'ro.adb.secure=0',
                        'ro.debuggable=1'])

    # Set the init.rc file
    info("Disabling init.rc reload_policy and setenforce")
    init = os.path.join(folder, 'ramdisk/init.rc')

    replace_lines(init,['setprop selinux.reload_policy 1'],['    setprop selinux.reload_policy 0']) # Nexus 6
    addline(init, '    setenforce 0', 'selinux.reload_policy', True)
    addline(init, '    setenforce 0', 'selinux.reload_policy', False)
    
    # Set sepolicy file
    info("Injecting selinux policy init kernel:security setenforce")
    policy = os.path.join(folder, 'ramdisk/sepolicy')

    out = check_output('tools/sepolicy-inject -s init -t kernel -c security -p setenforce -P {}'.format(policy).split(' ')) # Nexus 6, enable setenforce on boot

    # Patching the adbd
    try:
        sdk_version = int(check_output('adb shell getprop ro.build.version.sdk'.split(' ')))
    except:
        sdk_version = 21
    adbd_version = 21
    if sdk_version <= 15:
       adbd_version = 15 
    elif sdk_version <= 16:
       adbd_version = 16
    elif sdk_version <= 20:
       adbd_version = 17
    info("Found sdk version {}, using patch {}".format(sdk_version, adbd_version))
    
    adbd = os.path.join(ADBD_PATH, 'adbd.{}'.format(adbd_version))
    shutil.copyfile(adbd, os.path.join(folder, 'ramdisk/sbin/adbd'))
    
    success("Patch done on folder {}".format(folder))
    return 0

def _get_tmp():
    dirpath = tempfile.mkdtemp()
    shutil.rmtree(dirpath)
    return dirpath

def patch(args):
    '''usage: patch rom_folder/rom_image.img'''
    if not check(args, patch.__doc__):
        return 1
    else:
        rom = args[0]
        if os.path.isfile(rom):
            dirpath = _get_tmp()
            info("Unpacking {} to {}".format(rom, dirpath))
            unpacked = unpack([rom, dirpath])
            if unpacked is not None:
                do_patch(unpacked)

        elif os.path.isdir(rom):
            patched = do_patch(rom)
        else:
            error("Invalid path provided")

def doall(args):
    '''usage: doall rom_folder/rom_image.img'''
    try:
        rom = args[0]
    except:
        help(doall.__doc__)
        sys.exit(1)

    if os.path.isfile(rom):

	dirpath = _get_tmp()
	info("Unpacking {} to {}".format(rom, dirpath))
	unpacked = unpack([rom, dirpath])
	do_patch(unpacked)
	destination_path = get_path(args, OUT)
	packed = pack([unpacked, destination_path])
	if packed is not None:
	    flashed = flash([packed])

    elif os.path.isdir(rom):
	do_patch(rom)
	destination_path = get_path(args, OUT)
	packed = pack([rom, destination_path])
	if packed is not None:
	    flashed = flash([packed])
    else:
	error("Invalid path provided")
	sys.exit(1)

    wait_device()
    success("Returning a root shell:")
    os.system('adb shell')

def bootloader_exit(args):
    if check_device_boot():
        info('Restarting the device...')
        check_output('fastboot reboot'.split(' '))

def bootloader_init(args):
    if not check_device_boot():
        info('Restarting the device in bootloader mode...')
        try:
            check_output('adb reboot-bootloader'.split(' '))
        except:
            error('Device can not be rebooted automatically to bootloder mode')

def check_device_boot():
    out = check_output('fastboot devices'.split(' '))
    if 'fastboot' not in out:
        return False
    return True

def wait_device_boot():
    out = ""
    if not check_device_boot():
        info("Waiting for the device to be connected in bootloader mode... (Please connect the device)")
    while 'fastboot' not in out:
        time.sleep(0.5)
        out = check_output('fastboot devices'.split(' '))

def check_device():
    out = check_output('adb devices'.split(' '))
    if '\tdevice' not in out:
	return False
    return True

def wait_device():
    out = ""
    if not check_device():
        info("Waiting the device... (Please connect the device)")
    while '\tdevice' not in out:
        time.sleep(0.5) 
	out = check_output('adb devices'.split(' '))

def flash(args):
    '''usage: flash rom_image.img'''
    if not check(args, flash.__doc__):
        return 1
    else:
        rom = args[0]
        if not os.path.isfile(rom):
            error("Path provided not a file")
            sys.exit(1)

        bootloader_init(None)
        wait_device_boot()

        info('Flashing {}'.format(rom))
        p = Popen('fastboot flash boot {}'.format(rom).split(' '), stdout=PIPE, stderr=STDOUT)
        p.wait()
        out, err = p.communicate()

        if 'OKAY' in out:
            success('Successfully flashed {} to the device'.format(rom))
        else:
            error("Couldn't flash the image {}".format(rom))
            sys.exit(1)
        bootloader_exit(None)

def deps_resolver(none):
    if os.getuid() == 0:
        os.system('./deps_resolver.sh')
    else:
        error("Please run the deps resolver command with root permissions.")

if __name__ == '__main__':

    methods = {'unpack': unpack, 'pack': pack, 'patch': patch, 'flash': flash , 'bootloader': bootloader_init, 'reboot': bootloader_exit, 'doall':doall, 'deps':deps_resolver}

    if len(sys.argv) < 2:
        help()
        sys.exit(1)

    command = sys.argv[1]
    arguments = sys.argv[2:]

    if command in methods:
        out = methods[command](arguments)
        sys.exit(out)
    else:
        help()
        error("Command not found")

