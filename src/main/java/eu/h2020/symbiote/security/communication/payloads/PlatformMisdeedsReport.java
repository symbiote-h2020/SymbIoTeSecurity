package eu.h2020.symbiote.security.communication.payloads;

public abstract class PlatformMisdeedsReport {

    protected final int totalMisdeeds;

    public PlatformMisdeedsReport(int totalMisdeeds) {
        this.totalMisdeeds = totalMisdeeds;
    }

    public int getTotalMisdeeds() {
        return totalMisdeeds;
    }
}
