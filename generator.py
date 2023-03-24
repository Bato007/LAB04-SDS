import os, pefile, subprocess
import pandas as pd

malware_path = './MALWR'

class Section(object):
  def __init__(self, name, virtualAdress, virtualSize, rawDataSize) -> None:
    self.name = name
    self.virtualAddress = virtualAdress
    self.virtualSize = virtualSize
    self.rawDataSize = rawDataSize

class Malware(object):
  def __init__(self, index, filename, sections, dll, date) -> None:
    self.index = index
    self.filename = filename
    self.sections = sections
    self.dll = dll
    self.date = date

available = ['.text', '.data', '.rscr']
malwares = []
for i, filename in enumerate(os.listdir(malware_path)):
  if (filename == '.DS_Store'): continue

  full_path = malware_path + '/' + filename
  print('\n[GENERATOR]: Reading...', filename)

  subprocess.run(['upx', '-d', full_path])

  pe = pefile.PE(full_path)

  # Reading the sections
  sections = []
  virtualAddress = []
  virtualSize = []
  rawDataSize = []
  for section in pe.sections:
    sectionName = str(section.Name.decode('utf-8')).rstrip('\x00')
    sections.append(sectionName)
    virtualAddress.append(hex(section.VirtualAddress))
    virtualSize.append(hex(section.Misc_VirtualSize))
    rawDataSize.append(section.SizeOfRawData)
  print('[GENERATOR]: Getting sections', sections)
  section = Section(sections, virtualAddress, virtualSize, rawDataSize)

  # Reading the dll and function calls
  dllCalls = []
  functionsCalled = []
  print('[GENERATOR]: DLL calls and functions')
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dllCalls.append(entry.dll.decode('utf-8'))
    for function in entry.imports:
      functionsCalled.append(function.name.decode('utf-8'))

  date = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
  print('[GENERATOR]: Time Data Stamp:', date)
  malware = Malware(i, filename, section, [dllCalls, functionsCalled], date)
  malwares.append(malware)

# Now creates the csv
print('\n[GENERATOR]: Processing...')
columns = ['index', 'filename', 'sectionName', 'virtualAddress', 'virtualSize', 'rawDataSize', 'dll', 'functions', 'date']
df = pd.DataFrame(columns=columns)

for malware in malwares:
  df.loc[malware.index+1] = [
    malware.index,
    malware.filename,
    malware.sections.name,
    malware.sections.virtualAddress,
    malware.sections.virtualSize,
    malware.sections.rawDataSize,
    malware.dll[0],
    malware.dll[1],
    malware.date
  ]


df.to_csv('./data.csv', index=False)
print('[GENERATOR]: Finished')
