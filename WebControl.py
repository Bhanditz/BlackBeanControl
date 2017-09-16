#!python2

import broadlink, configparser
import sys, getopt
import time, binascii
import netaddr
import Settings
import web
from os import path
from Crypto.Cipher import AES

SettingsFile = configparser.ConfigParser()
SettingsFile.optionxform = str
SettingsFile.read(Settings.BlackBeanControlSettings)

DeviceName=''
DeviceIPAddress = ''
DevicePort = ''
DeviceMACAddres = ''
DeviceTimeout = ''
WebPort = ''

GlobalDevice = None

urls = (
    '/', 'WebHook',
)

class WebHook:
    def GET(self):
        global GlobalDevice

        input = web.input(device="", command="")

        DeviceName = input.device

        if DeviceName.strip() == '':
            return 'Device name parameter is mandatory'

        if SettingsFile.has_section(DeviceName.strip()):
            if SettingsFile.has_option(DeviceName.strip(), 'IPAddress'):
                DeviceIPAddress = SettingsFile.get(DeviceName.strip(), 'IPAddress')
            else:
                DeviceIPAddress = ''

            if SettingsFile.has_option(DeviceName.strip(), 'Port'):
                DevicePort = SettingsFile.get(DeviceName.strip(), 'Port')
            else:
                DevicePort = ''

            if SettingsFile.has_option(DeviceName.strip(), 'MACAddress'):
                DeviceMACAddress = SettingsFile.get(DeviceName.strip(), 'MACAddress')
            else:
                DeviceMACAddress = ''

            if SettingsFile.has_option(DeviceName.strip(), 'Timeout'):
                DeviceTimeout = SettingsFile.get(DeviceName.strip(), 'Timeout')
            else:
                DeviceTimeout = ''        
        else:
            return 'Device does not exist in BlackBeanControl.ini'

        if (DeviceName.strip() != '') and (DeviceIPAddress.strip() == ''):
            return 'IP address must exist in BlackBeanControl.ini for the selected device'

        if (DeviceName.strip() != '') and (DevicePort.strip() == ''):
            return 'Port must exist in BlackBeanControl.ini for the selected device'

        if (DeviceName.strip() != '') and (DeviceMACAddress.strip() == ''):
            return 'MAC address must exist in BlackBeanControl.ini for the selected device'

        if (DeviceName.strip() != '') and (DeviceTimeout.strip() == ''):
            return 'Timeout must exist in BlackBeanControl.ini for the selected device'

        if DeviceName.strip() != '':
            RealTimeout = DeviceTimeout.strip()
        else:
            RealTimeout = Settings.Timeout

        if RealTimeout.strip() == '':
            return 'Timeout must exist in BlackBeanControl.ini'
        else:
            RealTimeout = int(RealTimeout.strip())

        print("Device on IP %s:%s %s" % (DeviceIPAddress, DevicePort, DeviceMACAddress))

        ParsedMAC = netaddr.EUI(DeviceMACAddress)
        ParsedPort = int(DevicePort)
        RM3Device = broadlink.rm((DeviceIPAddress, ParsedPort), ParsedMAC)
        RM3Device.auth()

        if SettingsFile.has_option('Commands', input.command):
            CommandFromSettings = SettingsFile.get('Commands', input.command)
        else:
            CommandFromSettings = ''

        if CommandFromSettings.strip() != '':
            DecodedCommand = CommandFromSettings.decode('hex')
            RM3Device.send_data(DecodedCommand)
            return "OKAY"
        else:
            return "ERROR: Couldn't find %s" % (input.command)

if __name__ == '__main__':
    try:
        Options, args = getopt.getopt(sys.argv[1:], 'w:h', ['webport=','help'])
    except getopt.GetoptError:
        print('WebControl.py -w <Web port>')
        sys.exit(2)

    for Option, Argument in Options:
        if Option in ('-h', '--help'):
            print('WebControl.py -w <Web port>')
            sys.exit()
        elif Option in ('-w', '--webport'):
            WebPort = Argument
    try:
        RealPort = int(WebPort.strip())
    except:
        print("WebPort must be an integer")
        sys.exit(2)

    print("Starting up WebControl on port %s" % (RealPort))
    app = web.application(urls, globals())
    app.internalerror = web.debugerror
    web.httpserver.runsimple(app.wsgifunc(), ("0.0.0.0", RealPort))
    print("Exiting")
