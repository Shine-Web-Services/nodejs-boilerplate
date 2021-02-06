import { model, Schema } from 'mongoose'
const GroupsSchema = new Schema({
    title: {
        type: String,
    },
    description: {
        type: String,
    },
    cover_pic_url: {
        type: String,
        alias: 'coverPicUrl'
    },
    privacy_type: {
        type: Number,
        alias: 'privacyType'
    },
    invitation_type: {
        type: Number,
        alias: 'invitationType'
    },
    post_moderation: {
        type: String,
        alias: 'postModeration'
    },
    user_id: {
        type: String,
        alias: 'userId'
    },
    tag_ids: {
        type: String,
        alias: 'tagIds'
    },
    category_ids: {
        type: String,
        alias: 'categoryIds',
    },
    group_members: {
        type: String,
        alias: 'groupMembers'
    },
    invite_type: {
        type: Number,
        alias: 'inviteType',
    },
    invite_feature: {
        type: Number,
        alias: 'inviteFeature'
    },
    date_created: {
        type: Date,
        alias: 'dateCreated',
    },
    date_updated: {
        type: Date,
        alias: 'dateUpdated',
    },
    is_deleted: {
        type: Number,
        alias: 'isDeleted'
    },
})

export const Groups = model('groups', GroupsSchema)