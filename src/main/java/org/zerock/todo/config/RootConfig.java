package org.zerock.todo.config;

import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
@Configuration
public class RootConfig {
    @Bean // Modelmapper 커스텀
    public ModelMapper getMapper() {
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration()
                    .setFieldMatchingEnabled(true) // 이름에 따른 자동 맵핑
                    .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE) // private 허용
                    .setMatchingStrategy(MatchingStrategies.LOOSE); // 이름이 비슷해도 맵핑
        return modelMapper;
    }
}
