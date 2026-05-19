package com.adobexp.infralytiqs.scheduler.internal;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AemStorageUnitsTest {

    @Test
    void oneGbIs1000Mb() {
        assertEquals(1000d, AemStorageUnits.parseSizeToDecimalMegabytes("1 GB"), 0.001);
    }

    @Test
    void oneTbIsOneMillionMb() {
        assertEquals(1_000_000d, AemStorageUnits.parseSizeToDecimalMegabytes("1 TB"), 0.001);
    }

    @Test
    void eightPointFourTbFromAemCsv() {
        assertEquals(8_400_000d, AemStorageUnits.parseSizeToDecimalMegabytes("8.4 TB"), 0.001);
    }

    @Test
    void damRootRowFromSharadReport() {
        assertEquals(59_400_000d, AemStorageUnits.parseSizeToDecimalMegabytes("59.4 TB"), 1000d);
    }

    @Test
    void rollupPxFromArcChildInMb() {
        DamLevel1FolderRollup rollup = new DamLevel1FolderRollup();
        rollup.onCsvRow("/content/dam/px/arc", 8_400_000d, 142654);
        assertEquals(1, rollup.syntheticLevel1Rows().size());
        assertEquals(8_400_000d, rollup.syntheticLevel1Rows().get(0).sizeMb, 0.001);
    }

    @Test
    void level1RowFromCsvNeedsNoSyntheticRollup() {
        DamLevel1FolderRollup rollup = new DamLevel1FolderRollup();
        rollup.onCsvRow("/content/dam/whitelabel", 355.5, 21);
        rollup.markEmitted("/content/dam/whitelabel");
        assertTrue(rollup.syntheticLevel1Rows().isEmpty());
    }
}
