import { Controller, Get, Post, Body, Param, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiConsumes, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { FormDataRequest } from 'nestjs-form-data';
import { CreateFileDto } from './dto/create-files.dto';
import { FilesService } from './files.service';
import { FastifyReply } from 'fastify';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';
import { CheckAbilities } from 'src/common/decorators/abilities.decorator';
import { Action, Role } from 'src/common/types/global.type';
import { SkipThrottle, Throttle } from '@nestjs/throttler';

@ApiTags('Files')
@Controller('upload/files')
export class FilesController {
  constructor(private readonly filesService: FilesService) { }

  @ApiOperation({ description: 'Upload Files. Multiple files can be uploaded', summary: 'Upload File' })
  @ApiResponse({ status: 201, description: 'Files uploaded successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request. Something is wrong with payload.' })
  @FormDataRequest()
  @ApiConsumes('multipart/formdata')
  @CheckAbilities({ action: Action.CREATE, subject: Role.USER })
  @ApiBearerAuth()
  @Post()
  @Throttle({ default: { limit: 1, ttl: 1 * 1000 } }) // upload one file per second
  upload(@Body() createFileDto: CreateFileDto) {
    return this.filesService.upload(createFileDto);
  }

  @ApiOperation({ description: 'Get file by slug', summary: 'Get File' })
  @ApiResponse({ status: 200, description: 'File fetched successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  @SkipThrottle()
  @Public()
  @Get('get-file/:slug')
  getFile(@Param("slug") slug: string, @Res() res: FastifyReply) {
    return this.filesService.serveFile(slug, res);
  }
}
