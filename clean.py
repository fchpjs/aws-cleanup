# read config
import json
config_file = open('config.json').read()
config = json.loads(config_file)

# initialize cleaner
from classes.cleaner import Cleaner
cleaner = Cleaner(config)
cleaner.clean_all()