package com.adobexp.infralytiqs.scheduler.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Optional synthetic level-1 rows when a tenant CSV omits {@code /content/dam/{name}}.
 *
 * <p>Full DAM reports (e.g. Sharad-Disk-Tracking-Report.csv) include level-1 folders and a
 * final {@code /content/dam} row; this rollup is a safety net for partial tenant exports.
 */
public final class DamLevel1FolderRollup {

    public static final String DAM_ROOT = "/content/dam";

    private final Map<String, Double> level1SizeSum = new HashMap<>();
    private final Map<String, Long> level1AssetSum = new HashMap<>();
    private final Map<String, Double> level1DirectSize = new HashMap<>();
    private final Set<String> emittedPaths = new HashSet<>();

    public void onCsvRow(String folderPath, double sizeMb, int assetCount) {
        if (folderPath == null || folderPath.isEmpty()) {
            return;
        }
        String path = folderPath.trim();
        if (!path.startsWith(DAM_ROOT + "/")) {
            return;
        }
        String rest = path.substring((DAM_ROOT + "/").length());
        if (rest.isEmpty()) {
            return;
        }
        int slash = rest.indexOf('/');
        String level1Name = slash < 0 ? rest : rest.substring(0, slash);
        String level1Path = DAM_ROOT + "/" + level1Name;

        if (slash < 0) {
            level1DirectSize.put(level1Path, sizeMb);
            level1AssetSum.put(level1Path, (long) assetCount);
            return;
        }

        String childSegment = rest.substring(slash + 1);
        if (childSegment.indexOf('/') >= 0) {
            return;
        }

        String immediateChildPath = level1Path + "/" + childSegment;
        if (!path.equals(immediateChildPath)) {
            return;
        }

        level1SizeSum.merge(level1Path, sizeMb, Double::sum);
        level1AssetSum.merge(level1Path, (long) assetCount, Long::sum);
    }

    public void markEmitted(String folderPath) {
        if (folderPath != null && !folderPath.isEmpty()) {
            emittedPaths.add(folderPath.trim());
        }
    }

    public List<RollupRow> syntheticLevel1Rows() {
        List<RollupRow> out = new ArrayList<>();
        Set<String> level1Paths = new HashSet<>();
        level1Paths.addAll(level1SizeSum.keySet());
        level1Paths.addAll(level1DirectSize.keySet());

        for (String level1Path : level1Paths) {
            double childSum = level1SizeSum.getOrDefault(level1Path, 0d);
            double direct = level1DirectSize.getOrDefault(level1Path, 0d);
            double totalSize = childSum > 0 ? Math.max(childSum, direct) : direct;
            if (totalSize <= 0) {
                continue;
            }
            long assets = level1AssetSum.getOrDefault(level1Path, 0L);
            boolean needsEmit = !emittedPaths.contains(level1Path)
                    || (childSum > 0 && childSum > direct);
            if (needsEmit) {
                out.add(new RollupRow(level1Path, nameOf(level1Path), totalSize, safeInt(assets)));
            }
        }
        return out;
    }

    public static final class RollupRow {
        public final String path;
        public final String name;
        public final double sizeMb;
        public final int assetCount;

        public RollupRow(String path, String name, double sizeMb, int assetCount) {
            this.path = path;
            this.name = name;
            this.sizeMb = sizeMb;
            this.assetCount = assetCount;
        }
    }

    private static String nameOf(String path) {
        int idx = path.lastIndexOf('/');
        return idx < 0 ? path : path.substring(idx + 1);
    }

    private static int safeInt(long v) {
        if (v > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }
        if (v < 0) {
            return 0;
        }
        return (int) v;
    }
}
