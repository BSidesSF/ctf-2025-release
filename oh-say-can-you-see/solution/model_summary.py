#!/usr/bin/env python3

import sys

from keras.models import load_model

model = load_model(sys.argv[1])
print(model.get_config())
model.summary()
