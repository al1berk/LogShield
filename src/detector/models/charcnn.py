"""Optional character convolutional baseline."""

from __future__ import annotations

import os

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

try:
    from tensorflow import keras
    from tensorflow.keras import layers
except ImportError:  # pragma: no cover
    import keras
    from keras import layers


def build_charcnn(vocab_size: int, max_len: int, name: str = "logshield_charcnn") -> keras.Model:
    char_input = keras.Input(shape=(max_len,), name="char_input")
    x = layers.Embedding(vocab_size, 64, name="char_embedding")(char_input)
    branches = []
    for kernel_size in (3, 5, 7):
        branch = layers.Conv1D(96, kernel_size, activation="relu", padding="same")(x)
        branch = layers.GlobalMaxPooling1D()(branch)
        branches.append(branch)
    x = layers.Concatenate()(branches)
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(0.25)(x)
    output = layers.Dense(1, activation="sigmoid")(x)
    model = keras.Model(inputs=char_input, outputs=output, name=name)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model
