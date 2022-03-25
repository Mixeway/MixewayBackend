/*
 * @created  2020-08-27 : 14:48
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.utils;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class SecurityGatewayEntry {

    private int sastCritical;
    private int sastHigh;
    private int sastMedium;
    private int sastLow;
    private int osCritical;
    private int osHigh;
    private int osMedium;
    private int osLow;
    private int imageHigh;
    private int imageMedium;
    private int imageLow;
    private int webHigh;
    private int webMedium;
    private int webLow;
    private boolean passed;
}