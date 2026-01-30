/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.util;

import com.hypixel.hytale.codec.util.RawJsonReader;
import com.hypixel.hytale.math.util.MathUtil;
import com.hypixel.hytale.protocol.ColorAlpha;
import com.hypixel.hytale.protocol.ColorLight;
import java.awt.Color;
import java.io.IOException;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ColorParseUtil {
    public static final Pattern HEX_COLOR_PATTERN = Pattern.compile("^\\s*#([0-9a-fA-F]{3}){1,2}\\s*$");
    public static final Pattern HEX_ALPHA_COLOR_PATTERN = Pattern.compile("^\\s*#([0-9a-fA-F]{4}){1,2}\\s*$");
    public static final Pattern RGB_COLOR_PATTERN = Pattern.compile("^\\s*rgb\\((\\s*[0-9]{1,3}\\s*,){2}\\s*[0-9]{1,3}\\s*\\)\\s*$");
    public static final Pattern RGBA_COLOR_PATTERN = Pattern.compile("^\\s*rgba\\((\\s*[0-9]{1,3}\\s*,){3}\\s*[0,1](.[0-9]*)?\\s*\\)\\s*$");
    public static final Pattern RGBA_HEX_COLOR_PATTERN = Pattern.compile("^\\s*rgba\\(\\s*#([0-9a-fA-F]{3}){1,2}\\s*,\\s*[0,1](.[0-9]*)?\\s*\\)\\s*$");

    @Nullable
    public static ColorAlpha readColorAlpha(@Nonnull RawJsonReader reader) throws IOException {
        reader.consumeWhiteSpace();
        return switch (reader.peek()) {
            case 35 -> ColorParseUtil.readHexStringToColorAlpha(reader);
            case 114 -> ColorParseUtil.readRgbaStringToColorAlpha(reader);
            default -> null;
        };
    }

    @Nullable
    public static ColorAlpha parseColorAlpha(@Nonnull String stringValue) {
        if (HEX_ALPHA_COLOR_PATTERN.matcher(stringValue).matches()) {
            return ColorParseUtil.hexStringToColorAlpha(stringValue);
        }
        if (RGBA_HEX_COLOR_PATTERN.matcher(stringValue).matches()) {
            return ColorParseUtil.rgbaHexStringToColor(stringValue);
        }
        if (RGBA_COLOR_PATTERN.matcher(stringValue).matches()) {
            return ColorParseUtil.rgbaDecimalStringToColor(stringValue);
        }
        return null;
    }

    @Nullable
    public static com.hypixel.hytale.protocol.Color readColor(@Nonnull RawJsonReader reader) throws IOException {
        reader.consumeWhiteSpace();
        return switch (reader.peek()) {
            case 35 -> ColorParseUtil.readHexStringToColor(reader);
            case 114 -> ColorParseUtil.readRgbStringToColor(reader);
            default -> null;
        };
    }

    @Nullable
    public static com.hypixel.hytale.protocol.Color parseColor(@Nonnull String stringValue) {
        if (HEX_COLOR_PATTERN.matcher(stringValue).matches()) {
            return ColorParseUtil.hexStringToColor(stringValue);
        }
        if (RGB_COLOR_PATTERN.matcher(stringValue).matches()) {
            return ColorParseUtil.rgbStringToColor(stringValue);
        }
        return null;
    }

    @Nonnull
    public static com.hypixel.hytale.protocol.Color readHexStringToColor(@Nonnull RawJsonReader reader) throws IOException {
        int rgba = ColorParseUtil.readHexAlphaStringToRGBAInt(reader);
        return new com.hypixel.hytale.protocol.Color((byte)(rgba >> 24 & 0xFF), (byte)(rgba >> 16 & 0xFF), (byte)(rgba >> 8 & 0xFF));
    }

    @Nonnull
    public static com.hypixel.hytale.protocol.Color hexStringToColor(String color) {
        int rgba = ColorParseUtil.hexAlphaStringToRGBAInt(color);
        return new com.hypixel.hytale.protocol.Color((byte)(rgba >> 24 & 0xFF), (byte)(rgba >> 16 & 0xFF), (byte)(rgba >> 8 & 0xFF));
    }

    @Nonnull
    public static ColorAlpha readHexStringToColorAlpha(@Nonnull RawJsonReader reader) throws IOException {
        int rgba = ColorParseUtil.readHexAlphaStringToRGBAInt(reader);
        return new ColorAlpha((byte)(rgba & 0xFF), (byte)(rgba >> 24 & 0xFF), (byte)(rgba >> 16 & 0xFF), (byte)(rgba >> 8 & 0xFF));
    }

    @Nonnull
    public static ColorAlpha hexStringToColorAlpha(String color) {
        int rgba = ColorParseUtil.hexAlphaStringToRGBAInt(color);
        return new ColorAlpha((byte)(rgba & 0xFF), (byte)(rgba >> 24 & 0xFF), (byte)(rgba >> 16 & 0xFF), (byte)(rgba >> 8 & 0xFF));
    }

    public static int readHexAlphaStringToRGBAInt(@Nonnull RawJsonReader reader) throws IOException {
        reader.consumeWhiteSpace();
        reader.expect('#');
        reader.mark();
        try {
            int value = reader.readIntValue(16);
            int size = reader.getMarkDistance();
            switch (size) {
                case 3: {
                    value <<= 4;
                    value |= 0xF;
                }
                case 4: {
                    int red = value >> 12 & 0xF;
                    int green = value >> 8 & 0xF;
                    int blue = value >> 4 & 0xF;
                    int alpha = value & 0xF;
                    int n = red << 28 | red << 24 | green << 20 | green << 16 | blue << 12 | blue << 8 | alpha << 4 | alpha;
                    return n;
                }
                case 6: {
                    int n = value << 8 | 0xFF;
                    return n;
                }
                case 8: {
                    int n = value;
                    return n;
                }
            }
            throw new IllegalArgumentException("Invalid hex color size: " + size);
        }
        finally {
            reader.unmark();
            reader.consumeWhiteSpace();
        }
    }

    public static int hexAlphaStringToRGBAInt(String color) {
        Objects.requireNonNull(color, "Color must not be null");
        color = color.trim();
        if (color.isEmpty() || color.charAt(0) != '#') {
            throw new IllegalArgumentException("Hex color must start with '#'");
        }
        color = color.substring(1);
        int value = (int)Long.parseLong(color, 16);
        switch (color.length()) {
            case 3: {
                value <<= 4;
                value |= 0xF;
            }
            case 4: {
                int red = value >> 12 & 0xF;
                int green = value >> 8 & 0xF;
                int blue = value >> 4 & 0xF;
                int alpha = value & 0xF;
                return red << 28 | red << 24 | green << 20 | green << 16 | blue << 12 | blue << 8 | alpha << 4 | alpha;
            }
            case 6: {
                return value << 8 | 0xFF;
            }
            case 8: {
                return value;
            }
        }
        throw new IllegalArgumentException("Invalid hex color format: '" + color + "'");
    }

    public static int readHexStringToRGBInt(@Nonnull RawJsonReader reader) throws IOException {
        return ColorParseUtil.readHexAlphaStringToRGBAInt(reader) >>> 8;
    }

    public static int hexStringToRGBInt(String color) {
        return ColorParseUtil.hexAlphaStringToRGBAInt(color) >>> 8;
    }

    @Nonnull
    public static String colorToHexString(@Nullable com.hypixel.hytale.protocol.Color color) {
        return color == null ? "#FFFFFF" : ColorParseUtil.toHexString(color.red, color.green, color.blue);
    }

    @Nonnull
    public static String colorToHexAlphaString(@Nullable ColorAlpha color) {
        return color == null ? "#FFFFFFFF" : ColorParseUtil.toHexAlphaString(color.red, color.green, color.blue, color.alpha);
    }

    @Nonnull
    public static com.hypixel.hytale.protocol.Color readRgbStringToColor(@Nonnull RawJsonReader reader) throws IOException {
        reader.consumeWhiteSpace();
        reader.expect("rgb(", 0);
        reader.consumeWhiteSpace();
        byte red = reader.readByteValue();
        reader.consumeWhiteSpace();
        reader.expect(',');
        reader.consumeWhiteSpace();
        byte green = reader.readByteValue();
        reader.consumeWhiteSpace();
        reader.expect(',');
        reader.consumeWhiteSpace();
        byte blue = reader.readByteValue();
        reader.consumeWhiteSpace();
        reader.expect(')');
        reader.consumeWhiteSpace();
        return new com.hypixel.hytale.protocol.Color(red, green, blue);
    }

    @Nonnull
    public static com.hypixel.hytale.protocol.Color rgbStringToColor(String color) {
        Objects.requireNonNull(color, "Color must not be null");
        color = color.trim();
        if (!color.startsWith("rgb(") || color.charAt(color.length() - 1) != ')') {
            throw new IllegalArgumentException("Color must start with 'rgb(' and end with ')'");
        }
        String[] channels = (color = color.substring(4, color.length() - 1)).split(",");
        int channelLength = channels.length;
        if (channelLength != 3) {
            throw new IllegalArgumentException("rgb() but contain all 3 channels; r, g and b");
        }
        byte red = (byte)Integer.parseInt(channels[0].trim());
        byte green = (byte)Integer.parseInt(channels[1].trim());
        byte blue = (byte)Integer.parseInt(channels[2].trim());
        return new com.hypixel.hytale.protocol.Color(red, green, blue);
    }

    @Nonnull
    public static ColorAlpha readRgbaStringToColorAlpha(@Nonnull RawJsonReader reader) throws IOException {
        reader.consumeWhiteSpace();
        reader.expect("rgba(", 0);
        reader.consumeWhiteSpace();
        if (reader.peek() == 35) {
            return ColorParseUtil.readRgbaHexStringToColor(reader, false);
        }
        return ColorParseUtil.readRgbaDecimalStringToColor(reader, false);
    }

    @Nonnull
    public static ColorAlpha readRgbaDecimalStringToColor(@Nonnull RawJsonReader reader) throws IOException {
        return ColorParseUtil.readRgbaDecimalStringToColor(reader, true);
    }

    @Nonnull
    public static ColorAlpha readRgbaDecimalStringToColor(@Nonnull RawJsonReader reader, boolean readStart) throws IOException {
        if (readStart) {
            reader.consumeWhiteSpace();
            reader.expect("rgba(", 0);
            reader.consumeWhiteSpace();
        }
        byte red = reader.readByteValue();
        reader.consumeWhiteSpace();
        reader.expect(',');
        reader.consumeWhiteSpace();
        byte green = reader.readByteValue();
        reader.consumeWhiteSpace();
        reader.expect(',');
        reader.consumeWhiteSpace();
        byte blue = reader.readByteValue();
        reader.consumeWhiteSpace();
        reader.expect(',');
        reader.consumeWhiteSpace();
        byte alpha = (byte)MathUtil.clamp(reader.readFloatValue() * 255.0f, 0.0f, 255.0f);
        reader.consumeWhiteSpace();
        reader.expect(')');
        reader.consumeWhiteSpace();
        return new ColorAlpha(alpha, red, green, blue);
    }

    @Nonnull
    public static ColorAlpha rgbaDecimalStringToColor(String color) {
        Objects.requireNonNull(color, "Color must not be null");
        color = color.trim();
        if (!color.startsWith("rgba(") || color.charAt(color.length() - 1) != ')') {
            throw new IllegalArgumentException("Color must start with 'rgba(' and end with ')'");
        }
        String[] channels = (color = color.substring(5, color.length() - 1)).split(",");
        int channelLength = channels.length;
        if (channelLength != 4) {
            throw new IllegalArgumentException("rgba() but contain all 4 channels; r, g, b and a");
        }
        byte red = (byte)MathUtil.clamp(Integer.parseInt(channels[0].trim()), 0, 255);
        byte green = (byte)MathUtil.clamp(Integer.parseInt(channels[1].trim()), 0, 255);
        byte blue = (byte)MathUtil.clamp(Integer.parseInt(channels[2].trim()), 0, 255);
        byte alpha = (byte)MathUtil.clamp(Float.parseFloat(channels[3]) * 255.0f, 0.0f, 255.0f);
        return new ColorAlpha(alpha, red, green, blue);
    }

    @Nonnull
    public static ColorAlpha readRgbaHexStringToColor(@Nonnull RawJsonReader reader) throws IOException {
        return ColorParseUtil.readRgbaHexStringToColor(reader, true);
    }

    @Nonnull
    public static ColorAlpha readRgbaHexStringToColor(@Nonnull RawJsonReader reader, boolean readStart) throws IOException {
        if (readStart) {
            reader.consumeWhiteSpace();
            reader.expect("rgba(", 0);
            reader.consumeWhiteSpace();
        }
        long val = ColorParseUtil.readHexAlphaStringToRGBAInt(reader);
        reader.consumeWhiteSpace();
        reader.expect(',');
        reader.consumeWhiteSpace();
        byte alpha = (byte)MathUtil.clamp(reader.readFloatValue() * 255.0f, 0.0f, 255.0f);
        reader.consumeWhiteSpace();
        reader.expect(')');
        reader.consumeWhiteSpace();
        return new ColorAlpha(alpha, (byte)(val >> 24 & 0xFFL), (byte)(val >> 16 & 0xFFL), (byte)(val >> 8 & 0xFFL));
    }

    @Nonnull
    public static ColorAlpha rgbaHexStringToColor(String color) {
        Objects.requireNonNull(color, "Color must not be null");
        color = color.trim();
        if (!color.startsWith("rgba(") || color.charAt(color.length() - 1) != ')') {
            throw new IllegalArgumentException("Color must start with 'rgba(' and end with ')'");
        }
        String[] channels = (color = color.substring(5, color.length() - 1)).split(",");
        int channelLength = channels.length;
        if (channelLength != 2) {
            throw new IllegalArgumentException("rgba() but contain both #rgb and a");
        }
        long val = ColorParseUtil.hexAlphaStringToRGBAInt(channels[0].trim());
        byte alpha = (byte)MathUtil.clamp(Float.parseFloat(channels[1]) * 255.0f, 0.0f, 255.0f);
        return new ColorAlpha(alpha, (byte)(val >> 24 & 0xFFL), (byte)(val >> 16 & 0xFFL), (byte)(val >> 8 & 0xFFL));
    }

    @Nonnull
    public static String colorToHex(@Nullable Color color) {
        if (color == null) {
            return "#FFFFFF";
        }
        int argb = color.getRGB();
        int rgb = argb & 0xFFFFFF;
        return ColorParseUtil.toHexString(rgb);
    }

    @Nonnull
    public static String colorToHexAlpha(@Nullable Color color) {
        if (color == null) {
            return "#FFFFFFFF";
        }
        int argb = color.getRGB();
        int alpha = argb >> 24 & 0xFF;
        int rgb = argb & 0xFFFFFF;
        int rgba = rgb << 8 | alpha;
        return ColorParseUtil.toHexAlphaString(rgba);
    }

    public static int colorToARGBInt(@Nullable com.hypixel.hytale.protocol.Color color) {
        if (color == null) {
            return -1;
        }
        return 0xFF000000 | (color.red & 0xFF) << 16 | (color.green & 0xFF) << 8 | color.blue & 0xFF;
    }

    public static void hexStringToColorLightDirect(@Nonnull ColorLight colorLight, @Nonnull String color) {
        if (color.length() == 4) {
            colorLight.red = Byte.parseByte(color.substring(1, 2), 16);
            colorLight.green = Byte.parseByte(color.substring(2, 3), 16);
            colorLight.blue = Byte.parseByte(color.substring(3, 4), 16);
        } else {
            colorLight.red = (byte)(Integer.parseInt(color.substring(1, 3), 16) / 17);
            colorLight.green = (byte)(Integer.parseInt(color.substring(3, 5), 16) / 17);
            colorLight.blue = (byte)(Integer.parseInt(color.substring(5, 7), 16) / 17);
        }
    }

    @Nonnull
    public static String colorLightToHexString(@Nonnull ColorLight colorLight) {
        return ColorParseUtil.toHexString((byte)(colorLight.red * 17), (byte)(colorLight.green * 17), (byte)(colorLight.blue * 17));
    }

    @Nonnull
    public static String toHexString(byte red, byte green, byte blue) {
        return ColorParseUtil.toHexString((red & 0xFF) << 16 | (green & 0xFF) << 8 | blue & 0xFF);
    }

    @Nonnull
    public static String toHexString(int rgb) {
        String hexString = Integer.toHexString(rgb);
        return "#" + "0".repeat(6 - hexString.length()) + hexString;
    }

    @Nonnull
    public static String toHexAlphaString(byte red, byte green, byte blue, byte alpha) {
        return ColorParseUtil.toHexAlphaString((red & 0xFF) << 24 | (green & 0xFF) << 16 | (blue & 0xFF) << 8 | alpha & 0xFF);
    }

    @Nonnull
    public static String toHexAlphaString(int rgba) {
        String hexString = Integer.toHexString(rgba);
        return "#" + "0".repeat(8 - hexString.length()) + hexString;
    }
}

