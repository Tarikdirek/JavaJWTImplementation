package com.tobeto.pair5.services.dtos.carType.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GetCarTypeByIdResponse {
    private int id;
    private String name;
}
