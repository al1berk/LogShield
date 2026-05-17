"""Character-level Bidirectional Long Short-Term Memory model."""

from __future__ import annotations

import os

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

try:
    from tensorflow import keras
    from tensorflow.keras import layers
except ImportError:  # pragma: no cover
    import keras
    from keras import layers


def build_bilstm(vocab_size: int, max_len: int, signal_dim: int = 0, name: str = "logshield_bilstm") -> keras.Model:
    char_input = keras.Input(shape=(max_len,), name="char_input")
    x = layers.Embedding(vocab_size, 64, mask_zero=False, name="char_embedding")(char_input)
    x = layers.Bidirectional(layers.LSTM(128, return_sequences=True), name="bilstm_1")(x)
    x = layers.Dropout(0.30, name="dropout_1")(x)
    x = layers.Bidirectional(layers.LSTM(64), name="bilstm_2")(x)
    x = layers.Dropout(0.30, name="dropout_2")(x)

    inputs = [char_input]
    if signal_dim:
        signal_input = keras.Input(shape=(signal_dim,), name="canonical_signal")
        inputs.append(signal_input)
        x = layers.Concatenate(name="merge_signal")([x, signal_input])

    x = layers.Dense(64, activation="relu", name="dense_1")(x)
    output = layers.Dense(1, activation="sigmoid", name="output")(x)
    model = keras.Model(inputs=inputs, outputs=output, name=name)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall")],
    )
    return model
