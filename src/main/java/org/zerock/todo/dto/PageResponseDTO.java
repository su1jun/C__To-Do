package org.zerock.todo.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.List;

@Getter @ToString
public class PageResponseDTO<E> {
    private int page;
    private int size;
    private int total;

    private int start; //시작 페이지 번호
    private int end; //끝 페이지 번호

    private boolean prev; //이전 페이지의 존재 여부
    private boolean next; //다음 페이지의 존재 여부

    private List<E> dtoList;

    @Builder(builderMethodName = "withAll")
    public PageResponseDTO(
            PageRequestDTO pageRequestDTO,
            int total,
            List<E> dtoList
    ){
        if(total <= 0){
            return;
        }
        this.page = pageRequestDTO.getPage();
        this.size = pageRequestDTO.getSize();
        this.total = total;

        this.start = this.end - 9;
        this.end = (int)(Math.ceil(this.page / 10.0)) *  10;
        int last = (int)(Math.ceil((total / (double)size)));
        this.end = end > last ? last : end;

        this.prev = this.start > 1;
        this.next = total > this.end * this.size;

        this.dtoList = dtoList;
    }
}
