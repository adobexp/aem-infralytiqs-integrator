package com.adobexp.infralytiqs.filters;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Normalizes DAM asset paths extracted from download request URIs so encoded and decoded
 * variants (e.g. {@code Nivea%20A3%20x3.pdf} vs {@code Nivea A3 x3.pdf}) collapse to one value.
 */
final class DownloadPathNormalizer {

    private DownloadPathNormalizer() {}

    /**
     * URL-decodes the path when percent-encoding is present. Already-decoded paths are returned unchanged.
     */
    static String normalize(String resourcePath) {
        if (resourcePath == null || resourcePath.isEmpty()) {
            return "";
        }
        if (resourcePath.indexOf('%') < 0) {
            return resourcePath;
        }
        try {
            return URLDecoder.decode(resourcePath, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return resourcePath;
        }
    }
}
