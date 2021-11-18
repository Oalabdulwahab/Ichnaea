import os
import argparse
import xml.etree.ElementTree as ET
import time
import json
import csv
import difflib
import ctypes
from collections import OrderedDict

print("""
  _____     ____   __    __      __      _     ____      _____     ____    
 (_   _)   / ___) (  \  /  )    /  \    / )   (    )    / ___/    (    )   
   | |    / /      \ (__) /    / /\ \  / /    / /\ \   ( (__      / /\ \   
   | |   ( (        ) __ (     ) ) ) ) ) )   ( (__) )   ) __)    ( (__) )  
   | |   ( (       ( (  ) )   ( ( ( ( ( (     )    (   ( (        )    (   
  _| |__  \ \___    ) )( (    / /  \ \/ /    /  /\  \   \ \___   /  /\  \  
 /_____(   \____)  /_/  \_\  (_/    \__/    /__(  )__\   \____\ /__(  )__\ 
                                                                           
[*] Version 0.1 Beta 
[*] Compare IIS ApplicationHost files
""") 


class disable_file_system_redirection:
   _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
   _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
   def __enter__(self):
       self.old_value = ctypes.c_long()
       self.success = self._disable(ctypes.byref(self.old_value))
   def __exit__(self, type, value, traceback):
       if self.success:
           self._revert(self.old_value)


class Ichnaea:
    def __init__(self, file_path, history_path, extenstion, output):
        self.extenstion = extenstion
        self.config_files = self.list_dir(file_path)
        self.history_files = self.list_dir(history_path) + self.config_files
        self.tags = {}
        self.section = ['section', 'application']
        self.IIS_Sites = self.get_IIS_Sites_details(self.config_files[0])
        self.IIS_Modules = self.get_IIS_modules_details(self.config_files[0])
        self.mydata = []
        rfile = range(len(self.history_files) - 1)
        count = 0
        countnew = 1
        for count in rfile:
            self.diff_files(self.history_files[count], self.history_files[countnew])
            count += 1
            countnew = count + 1
        compareCols = ['History Filename', 'Modification Time', 'Added Lines', 'Removed Lines']
        sitesCols = ['Site name', 'Site id', 'path', 'Virtual Path', 'Physical Path']
        modulesCols = ['name', 'image']
        if output == "json":
            self.to_json(self.mydata, "CompareResult.json")
            self.to_json(self.IIS_Sites, "IIS_Sites.json")
            self.to_json(self.IIS_Modules, "IIS_Modules.json")
        else:
            self.to_csv(self.mydata, "CompareResult.csv", compareCols)
            self.to_csv(self.IIS_Sites, "IIS_Sites.csv", sitesCols)
            self.to_csv(self.IIS_Modules, "IIS_Modules.csv", modulesCols)

    # list csv file in a given path
    def list_dir(self, path):
        configFiles = []
        with disable_file_system_redirection():
            for root, dirs, files in os.walk(path):
                configFiles += [os.path.join(root, f)
                                for f in files if f.endswith(self.extenstion)]
            configFiles.sort()
            if not configFiles:
                print("No config files were found")
        return configFiles

    # Parse IIS glbal modules from Config File
    def get_IIS_modules_details(self, files):
        tree = ET.parse(files)
        root = tree.getroot()
        glopalModules = []
        for module in root.findall('./system.webServer/globalModules/'):
            glopalModules.append(module.attrib)
        return glopalModules

    # Parse IIS Sites from Config File
    def get_IIS_Sites_details(self, files):
        tree = ET.parse(files)
        root = tree.getroot()
        virDirs = []
        for site in root.findall('./system.applicationHost/sites/'):
            for app in site.findall('./'):
                try:
                    for virDir in app.findall('./'):
                        if virDir.tag == "virtualDirectory":
                            siteDict = site.attrib
                            appDict = app.attrib
                            virDirDict = virDir.attrib
                            siteDict = {'Site ' + k: v for k, v in siteDict.items()} 
                            virDirDict["Virtual Path"] = appDict["path"] + virDirDict["path"]
                            virDirDict["Physical Path"] = virDirDict.pop("physicalPath")
                            siteDict.update(appDict)
                            siteDict.update(virDirDict)
                            virDirs.append(OrderedDict(siteDict))
                except Exception as e:
                    print(e)
        return virDirs

    # compare file from list of files
    def diff_files(self, pre, new):  
        text1 = open(pre).readlines()
        text2 = open(new).readlines()
        for comp in difflib.unified_diff(text1, text2):
            if comp.startswith('++') or comp.startswith('---'):
                continue
            elif comp.startswith('-'):
                dic_data = {'History Filename': new, 'Modification Time': time.ctime(os.path.getmtime(new))} 
                dic_data.setdefault('Removed Lines', [])
                dic_data['Removed Lines'].append(comp.strip("- "))
                self.mydata.append(dic_data)
            elif comp.startswith('+'):
                dic_data = {'History Filename': new, 'Modification Time': time.ctime(os.path.getmtime(new))} 
                dic_data.setdefault('Added Lines', [])
                dic_data['Added Lines'].append(comp.strip().strip("+ "))
                self.mydata.append(dic_data)

    # write compare result to csv file
    def to_csv(self, file, filename, cols):  
        try:
            with open(filename, 'w', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=cols,delimiter=',', extrasaction='ignore', quotechar='|')
                writer.writeheader()
                writer.writerows(file)
                print ("File "+csv_file.name+" has been created")
        except IOError:
            print("I/O error")

    # write result to json file
    def to_json(self, file, filename):
        try:
            with open(filename, 'w', newline='') as json_file:
                json_file.write(json.dumps(file, indent=4))
                print ("File "+json_file.name+" has been created")
        except IOError:
            print("I/O error")


def main():
    parser = argparse.ArgumentParser(
        description="Read IIS config files history ", usage="will c  ",formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-f', '--file', help="Path of ApplicationHost.config file (default: %%windir%%\\system32\\inetsrv\\config)",default="%%windir%%\\system32\\inetsrv\\config", required=False)
    parser.add_argument('-p', '--files_path', help="Path of ApplicationHost.config history files (default: C:\\inetpub\\history)", required=False)
    parser.add_argument('-o', '--output_type', help="File Output type",choices=['json', 'csv'], default="csv", required=False )
    parser.add_argument('-m','--mode',choices=['Compare', 'Sites', 'Modules'],
        help="Compare: used to compare history files and get the result\n" 
        "Sites: used to parse the IIS sites\n"
        "Modules: used to parse the IIS global (Native) modules\n" 
        , required=False)
    args = parser.parse_args()
    ConfFile = 'C:\\Windows\\system32\\inetsrv\\config'
    historyFilesPath = 'C:\\inetpub\\history'
    if args.file:
        ConfFile = args.file
    if args.files_path:
        historyFilesPath = args.files_path

    Ichnaea(ConfFile, historyFilesPath, "applicationHost.config", args.output_type)


if __name__ == "__main__":
    main()
