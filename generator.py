import os, pefile
import pandas as pd

malware_path = './MALWR'

class Section(object):
  def __init__(self, name, virtualAdress, virtualSize, rawDataSize) -> None:
    self.name = name
    self.virtualAdress = virtualAdress
    self.virtualSize = virtualSize
    self.rawDataSize = rawDataSize

class DLL(object):
  def __init__(self, name, functions) -> None:
    self.name = name
    self.functions = functions

class Malware(object):
  def __init__(self, index, filename, sections, dll, date) -> None:
    self.index = index
    self.filename = filename
    self.sections = sections
    self.dll = dll
    self.date = date

malwares = []
for i, filename in enumerate(os.listdir(malware_path)):
  if (filename == '.DS_Store'): continue
  full_path = malware_path + '/' + filename
  print('\n[GENERATOR]: Reading...', full_path)

  pe = pefile.PE(full_path)

  # Reading the sections
  sections = []
  print('[GENERATOR]: Printing sections')
  for section in pe.sections:
    sectionInfo = Section(section.name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
    sections.append(sectionInfo)
    print(sectionInfo.name, sectionInfo.virtualAdress, sectionInfo.virtualSize, sectionInfo.rawDataSize)

  # Reading the dll and function calls
  dllCalls = []
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('[GENERATOR]: DLL calls\t', entry.dll.decode('utf-8'))

    functionsCalled = []
    print('[GENERATOR]: Functions')
    for function in entry.imports:
      functionsCalled.append(function.name.decode('utf-8'))
      print('\t', function.name)
    dllCalls.append(DLL(entry.dll, functionsCalled))

  date = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
  print('Time Data Stamp:', date)
  print('Time Data Stamp:', hex(pe.FILE_HEADER.TimeDateStamp))
  malware = Malware(i, filename, sections, dllCalls, date)
  malwares.append(malware)

# Now creates the csv
columns = ['index', 'filename', 'sections', 'dll', 'date']
df = pd.DataFrame(columns=columns)
for malware in malwares:

  sections = []
  for section in malware.sections:
    sections.append([section.name, section.virtualAdress, section.virtualSize, section.rawDataSize])

  dlls = []
  for dll in malware.dll:
    dictionary = {}
    dictionary['name'] = dll.name
    dictionary['functions'] = dll.functions
    dlls.append(dictionary)

  df.loc[malware.index+1] = [malware.index, malware.filename, sections ,dlls, malware.date]

df.to_csv('./data.csv', index=False)
print('[GENERATOR]: Finished')
