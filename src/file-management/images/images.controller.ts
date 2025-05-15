import { Controller, Get, Post, Body, Param, Query, Res } from '@nestjs/common';
import { ImagesService } from './images.service';
import { CreateImageDto } from './dto/create-image.dto';
import { ApiBearerAuth, ApiConsumes, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { FormDataRequest } from 'nestjs-form-data';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import { ImageQueryDto } from './dto/image-query.dto';
import { Action, AuthUser, Role } from 'src/common/types/global.type';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';
import { FastifyReply } from 'fastify';
import { CheckAbilities } from 'src/common/decorators/abilities.decorator';

@ApiTags('Images')
@Controller('upload/images')
export class ImagesController {
  constructor(private readonly imagesService: ImagesService) { }

  @ApiOperation({ description: 'Upload Images. Multiple images can be uploaded', summary: 'Upload Image' })
  @ApiResponse({ status: 201, description: 'Images uploaded successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request. Something is wrong with payload.' })
  @FormDataRequest({ limits: { fileSize: 5 * 1024 * 1024, files: 10 } })
  @ApiConsumes('multipart/formdata')
  @CheckAbilities({ action: Action.CREATE, subject: Role.USER })
  @ApiBearerAuth()
  @Post()
  @Throttle({ default: { limit: 1, ttl: 1 * 1000 } }) // upload one file per second
  upload(@Body() createImageDto: CreateImageDto, @CurrentUser() currentUser: AuthUser) {
    return this.imagesService.upload(createImageDto, currentUser);
  }

  @ApiOperation({ description: 'Get image by slug', summary: 'Get Image' })
  @ApiResponse({ status: 200, description: 'Image fetched successfully' })
  @ApiResponse({ status: 404, description: 'Image not found' })
  @SkipThrottle()
  @Public()
  @Get('get-image/:slug')
  getImage(@Param("slug") slug: string, @Query() queryDto: ImageQueryDto, @Res() res: FastifyReply) {
    return this.imagesService.serveImage(slug, queryDto, res);
  }
}
