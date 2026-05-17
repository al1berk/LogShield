"""Character-level BiLSTM with lightweight attention pooling."""

from __future__ import annotations

import os

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

try:
    from tensorflow import keras
    from tensorflow.keras import layers
except ImportError:  # pragma: no cover
    import keras
    from keras import layers


def build_bilstm_attention(vocab_size: int, max_len: int, name: str = "logshield_bilstm_attention") -> keras.Model:
    char_input = keras.Input(shape=(max_len,), name="char_input")
    x = layers.Embedding(vocab_size, 64, mask_zero=False, name="char_embedding")(char_input)
    x = layers.SpatialDropout1D(0.10, name="spatial_dropout")(x)
    sequence = layers.Bidirectional(layers.LSTM(96, return_sequences=True), name="bilstm")(x)

    attention = layers.Dense(1, name="attention_score")(sequence)
    attention = layers.Softmax(axis=1, name="attention_weights")(attention)

    weighted_context = layers.Dot(axes=(2, 1), name="attention_weighted_sum")(
        [layers.Permute((2, 1), name="attention_transpose")(attention), sequence]
    )
    weighted_context = layers.Flatten(name="attention_context")(weighted_context)
    max_context = layers.GlobalMaxPooling1D(name="global_max_context")(sequence)
    x = layers.Concatenate(name="context_concat")([weighted_context, max_context])

    x = layers.Dense(96, activation="relu", name="dense_1")(x)
    x = layers.Dropout(0.20, name="dropout")(x)
    x = layers.Dense(32, activation="relu", name="dense_2")(x)
    output = layers.Dense(1, activation="sigmoid", name="output")(x)
    model = keras.Model(inputs=char_input, outputs=output, name=name)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=8e-4),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall")],
    )
    return model
