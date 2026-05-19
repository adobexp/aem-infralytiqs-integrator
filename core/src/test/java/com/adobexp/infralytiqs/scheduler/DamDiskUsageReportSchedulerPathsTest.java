package com.adobexp.infralytiqs.scheduler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DamDiskUsageReportSchedulerPathsTest {

    @Test
    void resolveReportsApiTenantPathsUsesReportsApiTenantPathsFirst() {
        DamDiskUsageReportScheduler.DamDiskUsageReportCfg cfg = paths(
                new String[] {"/content/dam/garnier", "/content/dam/visa"},
                new String[] {"/content/dam"});
        assertArrayEquals(
                new String[] {"/content/dam/garnier", "/content/dam/visa"},
                DamDiskUsageReportScheduler.resolveReportsApiTenantPaths(cfg));
    }

    @Test
    void resolveReportsApiTenantPathsFallsBackToReportRootPaths() {
        DamDiskUsageReportScheduler.DamDiskUsageReportCfg cfg = paths(
                new String[0],
                new String[] {"/content/dam/dot", "/content/dam/ps"});
        assertArrayEquals(
                new String[] {"/content/dam/dot", "/content/dam/ps"},
                DamDiskUsageReportScheduler.resolveReportsApiTenantPaths(cfg));
    }

    @Test
    void normalizeDamPathListSplitsCommaSeparatedEntry() {
        assertEquals(2, DamDiskUsageReportScheduler.normalizeDamPathList(
                new String[] {"/content/dam/a,/content/dam/b"}).size());
    }

    private static DamDiskUsageReportScheduler.DamDiskUsageReportCfg paths(
            String[] reportsApiTenantPaths, String[] reportRootPaths) {
        return new DamDiskUsageReportScheduler.DamDiskUsageReportCfg() {
            @Override
            public Class<? extends java.lang.annotation.Annotation> annotationType() {
                return DamDiskUsageReportScheduler.DamDiskUsageReportCfg.class;
            }

            @Override
            public boolean enableScheduler() {
                return false;
            }

            @Override
            public String cronExpression() {
                return "";
            }

            @Override
            public String marker() {
                return "";
            }

            @Override
            public String[] reportRootPaths() {
                return reportRootPaths;
            }

            @Override
            public boolean includeRenditions() {
                return true;
            }

            @Override
            public String subService() {
                return "";
            }

            @Override
            public int maxDepth() {
                return 12;
            }

            @Override
            public int maxFoldersPerRun() {
                return 100_000;
            }

            @Override
            public int maxReportedFolderDepth() {
                return 0;
            }

            @Override
            public boolean runOnActivate() {
                return false;
            }

            @Override
            public String mode() {
                return "REPORTS_API";
            }

            @Override
            public String reportsApiBaseUrl() {
                return "";
            }

            @Override
            public String reportsApiUsername() {
                return "";
            }

            @Override
            public String reportsApiPassword() {
                return "";
            }

            @Override
            public String[] reportsApiTenantPaths() {
                return reportsApiTenantPaths;
            }

            @Override
            public int reportsApiPollIntervalSec() {
                return 60;
            }

            @Override
            public int reportsApiPollTimeoutSec() {
                return 600;
            }

            @Override
            public int reportsApiDownloadTimeoutSec() {
                return 600;
            }

            @Override
            public double reportsApiEmitPacingMaxFillRatio() {
                return 0.75d;
            }

            @Override
            public long reportsApiEmitPacingMaxWaitMs() {
                return 30_000L;
            }
        };
    }
}
