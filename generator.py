import os, pefile, subprocess
import pandas as pd

malware_path = './MALWR'

columns = [
  'index',
  'filename',
  'sectionName',
  'virtualAddress',
  'virtualSize',
  'rawDataSize', 
  'sectionNum',
  'baseOfCode',
  'imageBase',
  'sectionAlignment',
  'sizeOfInitializedData',
  'sizeOfCode',
  'dllCharacteristics',
  'addressOfEntryPoint',
  'date',
  'dll',
  'functions',
]
malwaresMetaData = []
for i, filename in enumerate(os.listdir(malware_path)):
  if (filename == '.DS_Store'): continue
  malware = []

  full_path = malware_path + '/' + filename
  print('\n[GENERATOR]: Reading...', filename)

  subprocess.run(['upx', '-d', full_path])

  pe = pefile.PE(full_path)
  fileHeader = pe.FILE_HEADER
  optionalHeader = pe.OPTIONAL_HEADER
  print(optionalHeader)

  # Reading the sections
  sections = []
  virtualAddress = []
  virtualSize = []
  rawDataSize = []
  for section in pe.sections:
    print(section)
    sectionName = str(section.Name.decode('utf-8')).rstrip('\x00')
    sections.append(sectionName)
    virtualAddress.append(hex(section.VirtualAddress))
    virtualSize.append(hex(section.Misc_VirtualSize))
    rawDataSize.append(section.SizeOfRawData)
  print('[GENERATOR]: Getting sections', sections)

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
  
  malwaresMetaData.append([
    i,
    filename,
    sections,
    virtualAddress,
    virtualSize,
    rawDataSize,
    fileHeader.NumberOfSections,
    optionalHeader.BaseOfCode,
    optionalHeader.ImageBase,
    optionalHeader.SectionAlignment,
    optionalHeader.SizeOfInitializedData,
    optionalHeader.SizeOfCode,
    optionalHeader.DllCharacteristics,
    optionalHeader.AddressOfEntryPoint,
    date,
    dllCalls,
    functionsCalled,
  ])

# Now creates the csv
print('\n[GENERATOR]: Processing...')
df = pd.DataFrame(data=malwaresMetaData, columns=columns)
df.to_csv('./data.csv', index=False)
print('[GENERATOR]: Finished')
