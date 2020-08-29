/*
 * @created  2020-08-27 : 14:48
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.pojo;

import lombok.Builder;
import lombok.Getter;

@Getter
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

    public int getSastCritical() {
        return sastCritical;
    }

    public void setSastCritical(int sastCritical) {
        this.sastCritical = sastCritical;
    }

    public int getOsCritical() {
        return osCritical;
    }

    public void setOsCritical(int osCritical) {
        this.osCritical = osCritical;
    }

    public int getSastHigh() {
        return sastHigh;
    }

    public void setSastHigh(int sastHigh) {
        this.sastHigh = sastHigh;
    }

    public int getSastMedium() {
        return sastMedium;
    }

    public void setSastMedium(int sastMedium) {
        this.sastMedium = sastMedium;
    }

    public int getSastLow() {
        return sastLow;
    }

    public void setSastLow(int sastLow) {
        this.sastLow = sastLow;
    }

    public int getOsHigh() {
        return osHigh;
    }

    public void setOsHigh(int osHigh) {
        this.osHigh = osHigh;
    }

    public int getOsMedium() {
        return osMedium;
    }

    public void setOsMedium(int osMedium) {
        this.osMedium = osMedium;
    }

    public int getOsLow() {
        return osLow;
    }

    public void setOsLow(int osLow) {
        this.osLow = osLow;
    }

    public int getImageHigh() {
        return imageHigh;
    }

    public void setImageHigh(int imageHigh) {
        this.imageHigh = imageHigh;
    }

    public int getImageMedium() {
        return imageMedium;
    }

    public void setImageMedium(int imageMedium) {
        this.imageMedium = imageMedium;
    }

    public int getImageLow() {
        return imageLow;
    }

    public void setImageLow(int imageLow) {
        this.imageLow = imageLow;
    }

    public int getWebHigh() {
        return webHigh;
    }

    public void setWebHigh(int webHigh) {
        this.webHigh = webHigh;
    }

    public int getWebMedium() {
        return webMedium;
    }

    public void setWebMedium(int webMedium) {
        this.webMedium = webMedium;
    }

    public int getWebLow() {
        return webLow;
    }

    public void setWebLow(int webLow) {
        this.webLow = webLow;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }
}
