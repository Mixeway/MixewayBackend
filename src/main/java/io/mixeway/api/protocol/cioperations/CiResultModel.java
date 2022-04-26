package io.mixeway.api.protocol.cioperations;

import lombok.*;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CiResultModel {
    private Long ok;
    private Long notOk;
}
