package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RunScan {
	private String target_id;
	private String profile_id;
	private Schedule schedule;

}
