import { Controller, Get, Post, Body, Patch, Param, Delete, Query, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiConsumes, ApiTags } from '@nestjs/swagger';
import { FormDataRequest } from 'nestjs-form-data';
import { CreateFileDto } from './dto/create-files.dto';
import { FilesService } from './files.service';
import { UpdateFileDto } from './dto/update-files.dto';
import { QueryDto } from 'src/common/dto/query.dto';
import { FastifyReply } from 'fastify';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';

@ApiBearerAuth()
@ApiTags('Upload Files')
@Controller('upload/files')
export class FilesController {
  constructor(private readonly filesService: FilesService) { }

  @Post()
  @FormDataRequest({ limits: { fileSize: 5 * 1024 * 1024, files: 10 } })
  @ApiConsumes('multipart/formdata')
  upload(@Body() createFileDto: CreateFileDto) {
    return this.filesService.upload(createFileDto);
  }

  @Get()
  findAll(@Query() queryDto: QueryDto) {
    return this.filesService.findAll(queryDto);
  }

  @Get('get-file/:slug')
  @Public() // TODO: this should not be public
  getFile(@Param("slug") slug: string, @Res() res: FastifyReply) {
    return this.filesService.serveFile(slug, res);
  }

  // @Get(':id')
  // findOne(@Param('id') id: string, @Res() res: Response) {
  //   return this.filesService.findOne(id);
  // }

  @Patch(':id')
  @FormDataRequest()
  update(@Param('id') id: string, @Body() updateFileDto: UpdateFileDto) {
    return this.filesService.update(id, updateFileDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.filesService.remove(id);
  }
}
