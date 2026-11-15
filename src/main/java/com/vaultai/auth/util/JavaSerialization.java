package com.vaultai.auth.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import org.springframework.core.ConfigurableObjectInputStream;

/**
 * Java serialization for objects stored as BLOBs (the same approach Spring Session uses).
 * Only data written by this application is read back.
 */
public final class JavaSerialization {

    private JavaSerialization() {
    }

    public static byte[] serialize(Serializable value) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
             ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject(value);
            output.flush();
            return bytes.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Could not serialize " + value.getClass().getName(), ex);
        }
    }

    public static <T> T deserialize(byte[] data, Class<T> type) {
        try (ObjectInputStream input = new ConfigurableObjectInputStream(
                new ByteArrayInputStream(data), JavaSerialization.class.getClassLoader())) {
            return type.cast(input.readObject());
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalStateException("Could not deserialize " + type.getName(), ex);
        }
    }
}