/*
 * @created  2020-11-05 : 20:15
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.integrations.checkmarx.model;

import com.univocity.parsers.annotations.Parsed;
import com.univocity.parsers.annotations.Trim;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CxResultCsvTemplate {
    @Trim
    @Parsed(field = "Query")
    private String query;

    @Parsed(field = "DestFileName")
    private String dstLocation;

    @Parsed(field = "DestLine")
    private String dstLine;

    @Parsed(field = "Result State")
    private String analysis;

    @Parsed(field = "Result Severity")
    private String severity;

    @Parsed(field = "Link")
    private String description;

    @Parsed(field = "Result Status")
    private String state;

}
