from base64 import encode
from tkinter import dnd
import tomli  # import tomllib in Python 3.11
import pprint
import os
import sys
import json
import csv
root_dir = os.path.dirname(os.path.abspath(__file__))
files = [name for name in os.listdir(root_dir) if not os.path.isfile(os.path.join(root_dir, name))]
for f_name in files:
  file = os.path.join(root_dir, f_name)
  os.chdir(file)
  file = os.getcwd()
  with open('result.json', 'a') as fp:
    for filename in os.listdir(file):
      if filename.endswith('.toml') and not filename.startswith('try'):
        with open(filename) as fileObj:
          content = fileObj.read()
          dnd_char = tomli.loads(content)
          json.dump(dnd_char, fp)
          fp.write("\n")

