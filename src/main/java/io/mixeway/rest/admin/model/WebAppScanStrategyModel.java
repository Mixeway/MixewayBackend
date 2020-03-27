package io.mixeway.rest.admin.model;

import javax.validation.constraints.Pattern;
import java.util.List;

public class WebAppScanStrategyModel {
    //TODO make it flexible
    @Pattern(regexp = "^$|\\bAcunetix|\\bBurpEE$", flags = Pattern.Flag.UNICODE_CASE)
    String apiStrategy;
    @Pattern(regexp = "^$|\\bAcunetix|\\bBurpEE$", flags = Pattern.Flag.UNICODE_CASE)
    String scheduledStrategy;
    @Pattern(regexp = "^$|\\bAcunetix|\\bBurpEE$", flags = Pattern.Flag.UNICODE_CASE)
    String guiStrategy;


    public String getApiStrategy() {
        return apiStrategy;
    }

    public void setApiStrategy(String apiStrategy) {
        this.apiStrategy = apiStrategy;
    }

    public String getScheduledStrategy() {
        return scheduledStrategy;
    }

    public void setScheduledStrategy(String scheduledStrategy) {
        this.scheduledStrategy = scheduledStrategy;
    }

    public String getGuiStrategy() {
        return guiStrategy;
    }

    public void setGuiStrategy(String guiStrategy) {
        this.guiStrategy = guiStrategy;
    }
}
