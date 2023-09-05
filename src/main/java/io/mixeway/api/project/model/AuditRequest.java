package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Pattern;

/**
 * @author gsiewruk
 */
@Getter
@Setter
public class AuditRequest {
    String location;
    String vulnerability;
}
