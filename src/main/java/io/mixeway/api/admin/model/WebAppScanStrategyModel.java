package io.mixeway.api.admin.model;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Pattern;

@Getter
@Setter
public class WebAppScanStrategyModel {
    //TODO make it flexible
    @Pattern(regexp = "^$|\\bAcunetix|\\bBurpEE$", flags = Pattern.Flag.UNICODE_CASE)
    String apiStrategy;
    @Pattern(regexp = "^$|\\bAcunetix|\\bBurpEE$", flags = Pattern.Flag.UNICODE_CASE)
    String scheduledStrategy;
    @Pattern(regexp = "^$|\\bAcunetix|\\bBurpEE$", flags = Pattern.Flag.UNICODE_CASE)
    String guiStrategy;
}
