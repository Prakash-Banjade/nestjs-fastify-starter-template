import { PageDto } from "src/common/dto/page.dto.";
import { PageMetaDto } from "src/common/dto/pageMeta.dto";
import { PageOptionsDto } from "src/common/dto/pageOptions.dto";
import { SelectQueryBuilder } from "typeorm";

export default async function paginatedData<T>(
    pageOptionsDto: PageOptionsDto,
    queryBuilder: SelectQueryBuilder<T>
) {
    const itemCount = await queryBuilder.getCount();
    const { entities } = await queryBuilder.getRawAndEntities();

    const pageMetaDto = new PageMetaDto({ itemCount, pageOptionsDto });

    return new PageDto(entities, pageMetaDto);
}