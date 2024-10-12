import { DataSource, EntityManager, Repository } from 'typeorm';
import { ENTITY_MANAGER_KEY } from '../interceptors/transaction.interceptor';
import { FastifyRequest } from 'fastify';

export class BaseRepository {
    constructor(private dataSource: DataSource, private request: FastifyRequest) { }

    protected getRepository<T>(entityCls: new () => T): Repository<T> {
        const entityManager: EntityManager =
            this.request[ENTITY_MANAGER_KEY] ?? this.dataSource.manager;
        return entityManager.getRepository(entityCls);
    }
}