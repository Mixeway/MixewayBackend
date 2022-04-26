package io.mixeway.api.protocol.cioperations;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Builder
@Getter
@Setter
@NoArgsConstructor
public class CiResultModel {
    private Long ok;
    private Long notOk;
}
