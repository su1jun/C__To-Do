package org.zerock.todo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.LocalDate;

@Data
@Builder
@AllArgsConstructor @NoArgsConstructor
public class PageRequestDTO {
    @Builder.Default
    private int page = 1;
    @Builder.Default
    private int size = 10;

    private String type; // 검색의 종류 t,c, w, tc,tw, twc
    private String keyword;
    //추가된 내용들
    private LocalDate from;
    private LocalDate to;
    private Boolean completed;

    public String[] getTypes(){
        if(type == null || type.isEmpty()){
            return null;
        }
        return type.split("");
    }

    public Pageable getPageable(String...props) {
        return PageRequest.of(this.page -1, this.size, Sort.by(props).descending());
    }

    private String link;

    public String getLink() {
        if(link == null){
            StringBuilder builder = new StringBuilder();
            builder.append("page=").append(this.page);
            builder.append("&size=").append(this.size);

            if(type != null && !type.isEmpty()){
                builder.append("&type=").append(type);
            }

            if(keyword != null){
                try {
                    builder.append("&keyword=").append(URLEncoder.encode(keyword, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                }
            }
            link = builder.toString();
        }
        return link;
    }
}
