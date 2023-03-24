import os, pefile
import pandas as pd

malware_path = './MALWR'

class Section(object):
  def __init__(self, name, virtualAdress, virtualSize, rawDataSize) -> None:
    self.name = name
    self.virtualAdress = virtualAdress
    self.virtualSize = virtualSize
    self.rawDataSize = rawDataSize

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
  functionsCalled = []
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('[GENERATOR]: DLL calls\t', entry.dll)

    print('[GENERATOR]: Functions')
    for function in entry.imports:
      functionsCalled.append(function.name.decode('utf-8'))
      print('\t', function.name)
    dllCalls.append(entry.dll.decode('utf-8'))

  date = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
  print('Time Data Stamp:', date)
  print('Time Data Stamp:', hex(pe.FILE_HEADER.TimeDateStamp))
  malware = Malware(i, filename, sections, [dllCalls, functionsCalled], date)
  malwares.append(malware)

# Now creates the csv
columns = ['index', 'filename', 'sections', 'dll', 'functions', 'date']
df = pd.DataFrame(columns=columns)
for malware in malwares:

  sections = []
  for section in malware.sections:
    sections.append([section.name, section.virtualAdress, section.virtualSize, section.rawDataSize])

  df.loc[malware.index+1] = [malware.index, malware.filename, sections, malware.dll[0], malware.dll[1], malware.date]

df.to_csv('./data.csv', index=False)
print('[GENERATOR]: Finished')
